package cpeskills

import "crypto/rand"

// generateUUIDv4 生成 UUID v4
func generateUUIDv4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// 设置 UUID v4 的变体和版本
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hexEncode(b)
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 36)
	for i, j := 0, 0; i < len(b); i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			buf[j] = '-'
			j++
		}
		buf[j] = hexDigits[b[i]>>4]
		buf[j+1] = hexDigits[b[i]&0x0f]
		j += 2
	}
	return string(buf)
}
