# gotor 中继（非出口）

## 启用

```bash
gotor -f examples/torrc.relay.sample
# 或
gotor ORPort 9001 Nickname gotorMiddle ExitRelay 0 DataDirectory ./data
```

## 已支持 torrc 键

ORPort、Nickname、ContactInfo、Address、ExitRelay、PublishServerDescriptor、
AssumeReachable、RelayBandwidthRate/Burst、BandwidthRate/Burst。

## 能力边界（首轮）

- OR 监听 + TLS + VERSIONS/CERTS/NETINFO
- CREATE2：经典 ntor（0x0002）与 ntor-v3（0x0003，含 CC 响应）
- NODEID = SHA1(PKCS#1 RSA 公钥)；ntor 密钥落盘 `keys/secret_onion_key_ntor`
- ExitRelay=1 时告警并仍按非出口运行

## 未完成

- 向权威发布服务描述符并获得共识标志
- 完整 RELAY 解密/出口流、DirPort、网桥
