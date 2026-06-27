# nft-forward-panel

涓€涓熀浜?nftables 鐨勭鍙ｈ浆鍙戠鐞嗚剼鏈紝鏀寔浜や簰寮忚彍鍗曞拰杞婚噺 Web 闈㈡澘銆?
## 鍔熻兘

- 鏅€?TCP/UDP DNAT 绔彛杞彂绠＄悊
- DNS 鍔ㄦ€佽浆鍙戠鐞?- Web 闈㈡澘娣诲姞銆佸垹闄ゃ€侀噸杞借鍒?- 鑷姩鐢熸垚 nftables 閰嶇疆
- 鍙€夐槻鐏绔彛鏀捐
- 閰嶇疆澶囦唤涓庤瘖鏂彍鍗?
## 浣跨敤

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/chenzai666/nft-forward-panel/main/nft.sh)
```

鎴栨墜鍔ㄤ笅杞藉悗鎵ц锛?
```bash
chmod +x nft.sh
sudo ./nft.sh
```

Web 闈㈡澘鍏ュ彛鍦ㄤ富鑿滃崟锛?
```text
9) Web 闈㈡澘绠＄悊
```

榛樿闈㈡澘绔彛涓?`4788`锛屽畨瑁呮椂鍙嚜瀹氫箟鐢ㄦ埛鍚嶃€佸瘑鐮佸拰绔彛銆?
## 瀹夊叏鎻愰啋

- 寤鸿鍙湪鍙俊缃戠粶銆乂PN 鎴栭槻鐏鐧藉悕鍗曞唴寮€鏀?Web 闈㈡澘绔彛銆?- 鑴氭湰 v1.6 璧烽粯璁や笉娓呯┖鍏ㄥ眬 nftables 瑙勫垯闆嗐€?- BBR + fq 缃戠粶浼樺寲鏀逛负鎵嬪姩纭鍚敤銆?- 鎵ц鍓嶄粛寤鸿鍏堝浠界幇鏈夎鍒欙細

```bash
nft list ruleset > /root/nft.rules.backup
iptables-save > /root/iptables.rules.backup
```

