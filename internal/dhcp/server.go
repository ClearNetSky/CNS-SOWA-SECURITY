package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
)

// DHCP message types
const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8
)

// DHCP option codes
const (
	OptSubnetMask    = 1
	OptRouter        = 3
	OptDNS           = 6
	OptHostname      = 12
	OptDomainName    = 15
	OptBroadcast     = 28
	OptRequestedIP   = 50
	OptLeaseTime     = 51
	OptMessageType   = 53
	OptServerID      = 54
	OptParameterList = 55
	OptRenewalTime   = 58
	OptRebindingTime = 59
	OptEnd           = 255
	OptPad           = 0
)

// DHCPPacket represents a parsed DHCP packet
type DHCPPacket struct {
	Op      byte             // Message op code: 1=BOOTREQUEST, 2=BOOTREPLY
	HType   byte             // Hardware address type
	HLen    byte             // Hardware address length
	Hops    byte             // Hops
	XID     uint32           // Transaction ID
	Secs    uint16           // Seconds elapsed
	Flags   uint16           // Flags
	CIAddr  net.IP           // Client IP address
	YIAddr  net.IP           // 'Your' (client) IP address
	SIAddr  net.IP           // Server IP address
	GIAddr  net.IP           // Gateway IP address
	CHAddr  net.HardwareAddr // Client hardware address
	SName   [64]byte         // Server host name
	File    [128]byte        // Boot file name
	Options map[byte][]byte  // DHCP options
}

// Server represents the DHCP server
type Server struct {
	cfg      *config.Config
	leases   map[string]*Lease // MAC -> Lease
	ipToMAC  map[string]string // IP -> MAC (reverse lookup)
	pool     *IPPool           // IP address pool
	mu       sync.RWMutex
	running  bool
	conn     *net.UDPConn
	done     chan struct{}
	serverIP net.IP
	dnsIP    net.IP
}

// Lease represents a DHCP lease
type Lease struct {
	IP        net.IP    `json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname"`
	ExpiresAt time.Time `json:"expires_at"`
	Static    bool      `json:"static"`
}

// IPPool manages available IP addresses
type IPPool struct {
	rangeStart net.IP
	rangeEnd   net.IP
	subnet     net.IPMask
}

// New creates a new DHCP server
func New(cfg *config.Config) *Server {
	return &Server{
		cfg:     cfg,
		leases:  make(map[string]*Lease),
		ipToMAC: make(map[string]string),
		done:    make(chan struct{}),
	}
}

// Start starts the DHCP server
func (s *Server) Start() error {
	if !s.cfg.DHCP.Enabled {
		log.Println("[DHCP] Server is disabled in config")
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("DHCP server is already running")
	}

	// Initialize IP pool
	s.pool = &IPPool{
		rangeStart: net.ParseIP(s.cfg.DHCP.RangeStart),
		rangeEnd:   net.ParseIP(s.cfg.DHCP.RangeEnd),
		subnet:     net.IPMask(net.ParseIP(s.cfg.DHCP.SubnetMask).To4()),
	}

	// Set server IP (gateway)
	s.serverIP = net.ParseIP(s.cfg.DHCP.GatewayIP)
	if s.serverIP == nil {
		s.serverIP = net.ParseIP("192.168.1.1")
	}

	// DNS server IP is this machine
	s.dnsIP = s.serverIP

	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 67,
	}

	var err error
	s.conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to start DHCP server: %w", err)
	}

	s.running = true
	log.Printf("[DHCP] Server started on %s (pool: %s - %s)", addr.String(), s.cfg.DHCP.RangeStart, s.cfg.DHCP.RangeEnd)

	go s.serve()
	go s.leaseCleanupLoop()

	return nil
}

// Stop stops the DHCP server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.done)
	if s.conn != nil {
		s.conn.Close()
	}
	s.running = false
	log.Println("[DHCP] Server stopped")
	return nil
}

// serve handles incoming DHCP packets
func (s *Server) serve() {
	buf := make([]byte, 1500)

	for {
		select {
		case <-s.done:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if s.running {
					log.Printf("[DHCP] Read error: %v", err)
				}
				continue
			}

			go s.handlePacket(buf[:n], addr)
		}
	}
}

// leaseCleanupLoop periodically removes expired leases
func (s *Server) leaseCleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupExpiredLeases()
		case <-s.done:
			return
		}
	}
}

// cleanupExpiredLeases removes expired dynamic leases
func (s *Server) cleanupExpiredLeases() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for mac, lease := range s.leases {
		if !lease.Static && lease.ExpiresAt.Before(now) {
			delete(s.ipToMAC, lease.IP.String())
			delete(s.leases, mac)
			log.Printf("[DHCP] Lease expired for %s (%s)", mac, lease.IP)
		}
	}
}

// handlePacket processes a DHCP packet
func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	if len(data) < 240 {
		return
	}

	pkt, err := parseDHCPPacket(data)
	if err != nil {
		log.Printf("[DHCP] Failed to parse packet: %v", err)
		return
	}

	// Must be a BOOTREQUEST (client -> server)
	if pkt.Op != 1 {
		return
	}

	// Get message type
	msgTypeData, ok := pkt.Options[OptMessageType]
	if !ok || len(msgTypeData) < 1 {
		return
	}

	msgType := msgTypeData[0]
	mac := pkt.CHAddr.String()

	log.Printf("[DHCP] Received %s from %s (XID: 0x%08x)", dhcpMsgTypeName(msgType), mac, pkt.XID)

	switch msgType {
	case DHCPDiscover:
		s.handleDiscover(pkt, addr)
	case DHCPRequest:
		s.handleRequest(pkt, addr)
	case DHCPRelease:
		s.handleRelease(pkt)
	case DHCPInform:
		s.handleInform(pkt, addr)
	case DHCPDecline:
		s.handleDecline(pkt)
	}
}

// handleDiscover processes DHCPDISCOVER - responds with DHCPOFFER
func (s *Server) handleDiscover(pkt *DHCPPacket, addr *net.UDPAddr) {
	mac := pkt.CHAddr.String()

	// Find an IP for this client
	offerIP := s.findIPForClient(mac, pkt)
	if offerIP == nil {
		log.Printf("[DHCP] No available IP for %s", mac)
		return
	}

	// Build DHCPOFFER response
	resp := s.buildResponse(pkt, DHCPOffer, offerIP)
	s.sendResponse(resp, addr)

	log.Printf("[DHCP] Sent OFFER %s to %s", offerIP, mac)
}

// handleRequest processes DHCPREQUEST - responds with DHCPACK or DHCPNAK
func (s *Server) handleRequest(pkt *DHCPPacket, addr *net.UDPAddr) {
	mac := pkt.CHAddr.String()

	// Get requested IP
	var requestedIP net.IP
	if reqIPData, ok := pkt.Options[OptRequestedIP]; ok && len(reqIPData) == 4 {
		requestedIP = net.IP(reqIPData)
	} else if !pkt.CIAddr.Equal(net.IPv4zero) {
		requestedIP = pkt.CIAddr
	}

	if requestedIP == nil {
		log.Printf("[DHCP] No requested IP from %s, sending NAK", mac)
		resp := s.buildResponse(pkt, DHCPNak, nil)
		s.sendResponse(resp, addr)
		return
	}

	// Verify the IP is acceptable
	if !s.isIPInRange(requestedIP) {
		log.Printf("[DHCP] Requested IP %s from %s is out of range, sending NAK", requestedIP, mac)
		resp := s.buildResponse(pkt, DHCPNak, nil)
		s.sendResponse(resp, addr)
		return
	}

	// Check if IP is already assigned to another MAC
	s.mu.RLock()
	existingMAC, taken := s.ipToMAC[requestedIP.String()]
	s.mu.RUnlock()

	if taken && existingMAC != mac {
		log.Printf("[DHCP] IP %s is already taken by %s, NAK to %s", requestedIP, existingMAC, mac)
		resp := s.buildResponse(pkt, DHCPNak, nil)
		s.sendResponse(resp, addr)
		return
	}

	// Assign the lease
	hostname := ""
	if hn, ok := pkt.Options[OptHostname]; ok {
		hostname = string(hn)
	}

	leaseDuration := time.Duration(s.cfg.DHCP.LeaseDuration) * time.Second

	s.mu.Lock()
	s.leases[mac] = &Lease{
		IP:        requestedIP,
		MAC:       mac,
		Hostname:  hostname,
		ExpiresAt: time.Now().Add(leaseDuration),
		Static:    false,
	}
	s.ipToMAC[requestedIP.String()] = mac
	s.mu.Unlock()

	// Send ACK
	resp := s.buildResponse(pkt, DHCPAck, requestedIP)
	s.sendResponse(resp, addr)

	log.Printf("[DHCP] Sent ACK %s to %s (%s), lease: %v", requestedIP, mac, hostname, leaseDuration)
}

// handleRelease processes DHCPRELEASE
func (s *Server) handleRelease(pkt *DHCPPacket) {
	mac := pkt.CHAddr.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if lease, ok := s.leases[mac]; ok {
		if !lease.Static {
			delete(s.ipToMAC, lease.IP.String())
			delete(s.leases, mac)
			log.Printf("[DHCP] Released lease %s for %s", lease.IP, mac)
		}
	}
}

// handleInform processes DHCPINFORM - sends configuration info without IP assignment
func (s *Server) handleInform(pkt *DHCPPacket, addr *net.UDPAddr) {
	mac := pkt.CHAddr.String()
	resp := s.buildResponse(pkt, DHCPAck, pkt.CIAddr)
	s.sendResponse(resp, addr)
	log.Printf("[DHCP] Sent INFORM ACK to %s", mac)
}

// handleDecline processes DHCPDECLINE - mark IP as unavailable
func (s *Server) handleDecline(pkt *DHCPPacket) {
	mac := pkt.CHAddr.String()
	if reqIPData, ok := pkt.Options[OptRequestedIP]; ok && len(reqIPData) == 4 {
		declinedIP := net.IP(reqIPData)
		log.Printf("[DHCP] Client %s declined IP %s", mac, declinedIP)
		// Remove the lease
		s.mu.Lock()
		if lease, ok := s.leases[mac]; ok {
			delete(s.ipToMAC, lease.IP.String())
			delete(s.leases, mac)
		}
		s.mu.Unlock()
	}
}

// findIPForClient finds an available IP for a client
func (s *Server) findIPForClient(mac string, pkt *DHCPPacket) net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if client already has a lease
	if lease, ok := s.leases[mac]; ok {
		return lease.IP
	}

	// Check if client requested a specific IP
	if reqIPData, ok := pkt.Options[OptRequestedIP]; ok && len(reqIPData) == 4 {
		reqIP := net.IP(reqIPData)
		if s.isIPInRange(reqIP) {
			if _, taken := s.ipToMAC[reqIP.String()]; !taken {
				return reqIP
			}
		}
	}

	// Find first available IP in the pool
	if s.pool.rangeStart == nil || s.pool.rangeEnd == nil {
		return nil
	}

	start := ipToUint32(s.pool.rangeStart.To4())
	end := ipToUint32(s.pool.rangeEnd.To4())

	for i := start; i <= end; i++ {
		ip := uint32ToIP(i)
		if _, taken := s.ipToMAC[ip.String()]; !taken {
			return ip
		}
	}

	return nil // Pool exhausted
}

// isIPInRange checks if an IP is within the DHCP pool range
func (s *Server) isIPInRange(ip net.IP) bool {
	if s.pool.rangeStart == nil || s.pool.rangeEnd == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	ipVal := ipToUint32(ip4)
	return ipVal >= ipToUint32(s.pool.rangeStart.To4()) && ipVal <= ipToUint32(s.pool.rangeEnd.To4())
}

// buildResponse constructs a DHCP response packet
func (s *Server) buildResponse(req *DHCPPacket, msgType byte, assignedIP net.IP) []byte {
	resp := make([]byte, 576) // Standard minimum DHCP packet size

	resp[0] = 2 // BOOTREPLY
	resp[1] = req.HType
	resp[2] = req.HLen
	resp[3] = 0 // Hops

	// Transaction ID
	binary.BigEndian.PutUint32(resp[4:8], req.XID)

	// Secs / Flags
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], req.Flags)

	// CIAddr (always 0 for OFFER/ACK unless INFORM)
	if msgType == DHCPAck && req.Options[OptMessageType] != nil && req.Options[OptMessageType][0] == DHCPInform {
		copy(resp[12:16], req.CIAddr.To4())
	}

	// YIAddr (assigned IP)
	if assignedIP != nil {
		copy(resp[16:20], assignedIP.To4())
	}

	// SIAddr (server IP)
	copy(resp[20:24], s.serverIP.To4())

	// GIAddr
	copy(resp[24:28], req.GIAddr.To4())

	// CHAddr (client hardware address)
	copy(resp[28:44], req.CHAddr)

	// Magic cookie
	copy(resp[236:240], []byte{99, 130, 83, 99})

	// DHCP Options
	offset := 240

	// Option 53: Message Type
	resp[offset] = OptMessageType
	resp[offset+1] = 1
	resp[offset+2] = msgType
	offset += 3

	// Option 54: Server Identifier
	resp[offset] = OptServerID
	resp[offset+1] = 4
	copy(resp[offset+2:offset+6], s.serverIP.To4())
	offset += 6

	if msgType != DHCPNak {
		// Option 51: Lease Time
		leaseTime := uint32(s.cfg.DHCP.LeaseDuration)
		resp[offset] = OptLeaseTime
		resp[offset+1] = 4
		binary.BigEndian.PutUint32(resp[offset+2:offset+6], leaseTime)
		offset += 6

		// Option 58: Renewal Time (T1 = 50% of lease)
		resp[offset] = OptRenewalTime
		resp[offset+1] = 4
		binary.BigEndian.PutUint32(resp[offset+2:offset+6], leaseTime/2)
		offset += 6

		// Option 59: Rebinding Time (T2 = 87.5% of lease)
		resp[offset] = OptRebindingTime
		resp[offset+1] = 4
		binary.BigEndian.PutUint32(resp[offset+2:offset+6], leaseTime*7/8)
		offset += 6

		// Option 1: Subnet Mask
		resp[offset] = OptSubnetMask
		resp[offset+1] = 4
		mask := net.ParseIP(s.cfg.DHCP.SubnetMask).To4()
		if mask == nil {
			mask = net.IP(net.IPv4Mask(255, 255, 255, 0))
		}
		copy(resp[offset+2:offset+6], mask)
		offset += 6

		// Option 3: Router (Gateway)
		resp[offset] = OptRouter
		resp[offset+1] = 4
		copy(resp[offset+2:offset+6], s.serverIP.To4())
		offset += 6

		// Option 6: DNS Server (our DNS)
		resp[offset] = OptDNS
		resp[offset+1] = 4
		copy(resp[offset+2:offset+6], s.dnsIP.To4())
		offset += 6

		// Option 28: Broadcast Address
		if assignedIP != nil && mask != nil {
			broadcast := make(net.IP, 4)
			ip4 := assignedIP.To4()
			for i := 0; i < 4; i++ {
				broadcast[i] = ip4[i] | ^mask[i]
			}
			resp[offset] = OptBroadcast
			resp[offset+1] = 4
			copy(resp[offset+2:offset+6], broadcast)
			offset += 6
		}
	}

	// End option
	resp[offset] = OptEnd
	offset++

	return resp[:offset]
}

// sendResponse sends a DHCP response
func (s *Server) sendResponse(data []byte, clientAddr *net.UDPAddr) {
	// DHCP responses are typically broadcast
	destAddr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: 68,
	}

	// If client has an IP (unicast capable), send directly if flags say so
	if clientAddr != nil && !clientAddr.IP.Equal(net.IPv4zero) {
		// Check broadcast flag (bit 15)
		flags := binary.BigEndian.Uint16(data[10:12])
		if flags&0x8000 == 0 {
			// Unicast to client
			destAddr = &net.UDPAddr{
				IP:   net.IP(data[16:20]),
				Port: 68,
			}
		}
	}

	if _, err := s.conn.WriteToUDP(data, destAddr); err != nil {
		log.Printf("[DHCP] Failed to send response: %v", err)
	}
}

// parseDHCPPacket parses raw bytes into a DHCPPacket
func parseDHCPPacket(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	pkt := &DHCPPacket{
		Op:      data[0],
		HType:   data[1],
		HLen:    data[2],
		Hops:    data[3],
		XID:     binary.BigEndian.Uint32(data[4:8]),
		Secs:    binary.BigEndian.Uint16(data[8:10]),
		Flags:   binary.BigEndian.Uint16(data[10:12]),
		CIAddr:  net.IP(data[12:16]),
		YIAddr:  net.IP(data[16:20]),
		SIAddr:  net.IP(data[20:24]),
		GIAddr:  net.IP(data[24:28]),
		CHAddr:  net.HardwareAddr(data[28 : 28+data[2]]),
		Options: make(map[byte][]byte),
	}

	copy(pkt.SName[:], data[44:108])
	copy(pkt.File[:], data[108:236])

	// Check magic cookie
	if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
		return nil, fmt.Errorf("invalid DHCP magic cookie")
	}

	// Parse options
	offset := 240
	for offset < len(data) {
		opt := data[offset]
		if opt == OptEnd {
			break
		}
		if opt == OptPad {
			offset++
			continue
		}

		if offset+1 >= len(data) {
			break
		}
		optLen := int(data[offset+1])
		if offset+2+optLen > len(data) {
			break
		}

		optData := make([]byte, optLen)
		copy(optData, data[offset+2:offset+2+optLen])
		pkt.Options[opt] = optData
		offset += 2 + optLen
	}

	return pkt, nil
}

// Utility functions

func ipToUint32(ip net.IP) uint32 {
	if len(ip) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func dhcpMsgTypeName(t byte) string {
	names := map[byte]string{
		1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
		5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", t)
}

// GetLeases returns all active leases
func (s *Server) GetLeases() []Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var leases []Lease
	now := time.Now()

	for _, lease := range s.leases {
		if lease.Static || lease.ExpiresAt.After(now) {
			leases = append(leases, *lease)
		}
	}

	return leases
}

// GetLeaseCount returns the number of active leases
func (s *Server) GetLeaseCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	now := time.Now()
	for _, lease := range s.leases {
		if lease.Static || lease.ExpiresAt.After(now) {
			count++
		}
	}
	return count
}

// AddStaticLease adds a static DHCP lease
func (s *Server) AddStaticLease(mac string, ip net.IP, hostname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if IP is already taken by another MAC
	if existingMAC, ok := s.ipToMAC[ip.String()]; ok && existingMAC != mac {
		return fmt.Errorf("IP %s is already assigned to %s", ip, existingMAC)
	}

	s.leases[mac] = &Lease{
		IP:        ip,
		MAC:       mac,
		Hostname:  hostname,
		ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour),
		Static:    true,
	}
	s.ipToMAC[ip.String()] = mac

	log.Printf("[DHCP] Added static lease: %s -> %s (%s)", mac, ip, hostname)
	return nil
}

// RemoveStaticLease removes a static DHCP lease
func (s *Server) RemoveStaticLease(mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if lease, ok := s.leases[mac]; ok {
		delete(s.ipToMAC, lease.IP.String())
		delete(s.leases, mac)
		log.Printf("[DHCP] Removed lease for %s", mac)
	}
}

// IsRunning returns whether the DHCP server is running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
