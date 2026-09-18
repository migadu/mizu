// Package cluster provides distributed coordination for Mizu instances using
// a peer-to-peer gossip protocol.
//
// # Overview
//
// The cluster package implements distributed features that allow multiple
// Mizu instances to coordinate and share state:
//
//	Connection State: Share connection counts across cluster
//	Rate Limits: Enforce rate limits cluster-wide
//	Leader Election: Coordinate TLS certificate management
//	Stats Sync: Share reputation data via S3
//
// The implementation uses hashicorp/memberlist for P2P gossip communication,
// which provides:
//
//	Fast failure detection
//	Automatic peer discovery
//	Encrypted communication
//	No single point of failure
//
// # Gossip Protocol
//
// Memberlist uses a gossip protocol for distributed state:
//
//  1. Each node maintains a membership list of all peers
//  2. Nodes periodically exchange membership information
//  3. State updates propagate through the cluster via gossip
//  4. Failed nodes are detected and removed from the cluster
//
// The protocol is eventually consistent and scales to hundreds of nodes.
//
// # Message Types
//
// The package defines several message types for gossip:
//
//	MessageTypeConnectionState: Share connection counts per IP
//	MessageTypeRateLimit: Share rate limit counters
//
// Messages are broadcast to all peers and merged using vector clocks
// to handle concurrent updates correctly.
//
// # Leader Election
//
// The package includes simple leader election for coordinating tasks
// that should run on only one node:
//
//	TLS certificate management (Let's Encrypt)
//	Periodic maintenance tasks
//	Cluster-wide operations
//
// Leader election is based on node IDs - the node with the lexicographically
// smallest ID becomes the leader. If the leader fails, a new leader is
// automatically elected.
//
// A node that has peers configured claims no leader until it has seen another
// member: alone, the smallest ID it knows is its own. If no peer can be reached
// within Config.LeaderGracePeriod (1 minute) it proceeds as a single-node
// cluster, so a node whose peers are down can still do leader work. While it is
// alone it retries the join every Config.RejoinInterval (15 seconds) - memberlist
// does not, and nodes started at the same moment can otherwise miss each other
// for good.
//
// # Security
//
// Communication between nodes is encrypted using AES-256-GCM with a
// shared secret key:
//
//	cluster.secret_key = "base64-encoded-32-byte-key"
//
// Or via environment variable:
//
//	CLUSTER_SECRET_KEY=<base64-key>
//
// Generate a secure key:
//
//	openssl rand -base64 32
//
// All nodes in the cluster MUST use the same secret key.
//
// # Configuration
//
// Cluster mode is configured in config.toml:
//
//	[cluster]
//	enabled = true
//	node_name = "mizu-1"  # Auto-detected if empty
//	bind_addr = "0.0.0.0"
//	bind_port = 7946  # Standard memberlist port
//	peers = [
//	    "mizu-1.example.com:7946",
//	    "mizu-2.example.com:7946",
//	]
//	secret_key = "${CLUSTER_SECRET_KEY}"
//
// # Peer Discovery
//
// Nodes discover each other through the configured peer list. Each node
// should list at least one other node to join the cluster. Once joined,
// membership information propagates via gossip.
//
// For dynamic environments (Kubernetes, AWS), nodes can discover peers via:
//
//	DNS SRV records
//	Kubernetes service discovery
//	Cloud provider APIs
//
// # Failure Detection
//
// Memberlist uses multiple mechanisms to detect failed nodes:
//
//	Direct probes: Periodic TCP probes to each node
//	Indirect probes: Ask other nodes to probe on your behalf
//	Suspicion: Gradual confidence buildup before declaring failure
//
// Typical detection time: 1-5 seconds for crashed nodes.
//
// # Network Partitions
//
// During a network partition, the cluster splits into multiple sub-clusters.
// Each sub-cluster continues operating independently. When the partition heals,
// the sub-clusters automatically merge and reconcile state using vector clocks.
//
// # Scaling
//
// The gossip protocol scales well:
//
//	3-10 nodes: Excellent performance, sub-second convergence
//	10-100 nodes: Good performance, few seconds convergence
//	100+ nodes: May need tuning of gossip intervals
//
// For very large clusters (1000+ nodes), consider using multiple clusters
// with a hierarchy.
//
// # Metrics
//
// Cluster metrics are exposed via Prometheus:
//
//	mizu_cluster_members_total: Current number of cluster members
//	mizu_cluster_leader{node}: Whether this node is the leader (0 or 1)
//	mizu_cluster_gossip_messages_total{type,direction}: Gossip message counts
//
// # Example Usage
//
//	// Create cluster manager
//	mgr, err := cluster.New(
//	    config.Cluster.NodeName,
//	    config.Cluster.BindAddr,
//	    config.Cluster.BindPort,
//	    config.Cluster.Peers,
//	    config.Cluster.SecretKey,
//	    logger,
//	)
//	if err != nil {
//	    log.Fatal("Failed to create cluster:", err)
//	}
//
//	// Start cluster
//	if err := mgr.Start(); err != nil {
//	    log.Fatal("Failed to start cluster:", err)
//	}
//	defer mgr.Stop()
//
//	// Check if leader
//	if mgr.IsLeader() {
//	    // Perform leader-only tasks
//	}
//
//	// Broadcast message
//	msg := cluster.Message{
//	    Type: cluster.MessageTypeConnectionState,
//	    Data: stateData,
//	}
//	mgr.Broadcast(msg)
//
// # Thread Safety
//
// All types are thread-safe and can be used concurrently from multiple
// goroutines.
package cluster
