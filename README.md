# gunyah_host_mod

Host-side out-of-tree kernel modules for DroidVM's GuestAccept memory sharing
(crosvm + Qualcomm Gunyah), per GKI version.

- **GKI6.6/** — `gunyah_share_66`: runtime SHARE_BLOB `/dev/gunyah_share` for
  upstream GKI 6.6 gunyah (v5: liveness-GC auto-reclaim + bounded share retry).
- **GKI6.1/**, **GKI6.12/** — placeholders for the 6.1 / 6.12 GKI ports.
