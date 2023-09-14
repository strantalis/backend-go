package crypto

func KeySplit(key []byte, splits int) [][]byte {
	keyLength := len(key)
	var keySplits [][]byte
	for i := 0; i < splits-1; i++ {
		nonce, _ := GenerateKey(keyLength)
		// XOR the keys together
		for i, b := range nonce {
			key[i] ^= b
		}
		keySplits = append(keySplits, nonce)
	}
	keySplits = append(keySplits, key)
	return keySplits
}

func KeyMerge(splits [][]byte) []byte {
	var key = splits[0]
	for _, split := range splits[1:] {
		for i, b := range split {
			key[i] ^= b
		}
	}
	return key
}
