package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/TykTechnologies/murmur3"
	"github.com/buger/jsonparser"
)

var (
	HashSha256    = "sha256"
	HashMurmur32  = "murmur32"
	HashMurmur64  = "murmur64"
	HashMurmur128 = "murmur128"

	reader = bufio.NewReader(os.Stdin)
	algo   hash.Hash
)

// `{"` in base64
const B64JSONPrefix = "ey"

func main() {
	algo = GetAlgo()
	HashString()
}

func HashString() {
	for {

		fmt.Println("Input your Tyk Key ID or whatever String you want to hash, or * to exit:")

		input, err := reader.ReadString('\n')

		if err != nil {
			fmt.Println("Unable to Process your Value")
		} else {
			input = strings.TrimSuffix(input, "\n")
			if input == "*" {
				break
			}

			fmt.Printf("Calculating the Hash for %s\n", input)
			fmt.Printf("The Tyk Hash is %s\n", HashStr2(input))
			reset()
		}
	}
}

func GetAlgo() hash.Hash {
	fmt.Println("Select your Hashing Algorithm:")
	fmt.Println("1. SHA256")
	fmt.Println("2. MurMur32")
	fmt.Println("3. MurMur64")
	fmt.Println("4. MurMur128")
	// ReadString will block until the delimiter is entered
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("No Option Selected, reverting to Default, MurMur32")
		return murmur3.New32()
	}

	// remove the delimeter from the string
	option, _ := strconv.Atoi(strings.TrimSuffix(input, "\n"))

	switch option {
	case 1:
		fmt.Println("Selected SHA256")
		return sha256.New()
	case 2:
		fmt.Println("Selected MurMur32")
		return murmur3.New32()
	case 3:
		fmt.Println("Selected MurMur64")
		return murmur3.New64()
	case 4:
		fmt.Println("Selected MurMur128")
		return murmur3.New128()
	default:
		fmt.Println("Invalid Option Selected, reverting to Default, MurMur32")
		return murmur3.New32()
	}
}

// AddFooBarHeader adds custom "Foo: Bar" header to the request
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
}

func TokenHashAlgo(token string) string {
	// Legacy tokens not b64 and not JSON records
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			hashAlgo, _ := jsonparser.GetString(jsonToken, "h")
			return hashAlgo
		}
	}

	return ""
}

func TokenID(token string) (id string, err error) {
	jsonToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	return jsonparser.GetString(jsonToken, "id")
}

func TokenOrg(token string) string {
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			// Checking error in case if it is a legacy tooken which just by accided has the same b64JSON prefix
			if org, err := jsonparser.GetString(jsonToken, "org"); err == nil {
				return org
			}
		}
	}

	// 24 is mongo bson id length
	if len(token) > 24 {
		return token[:24]
	}

	return ""
}

func hashFunction(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case HashSha256:
		return sha256.New(), nil
	case HashMurmur64:
		return murmur3.New64(), nil
	case HashMurmur128:
		return murmur3.New128(), nil
	case "", HashMurmur32:
		return murmur3.New32(), nil
	default:
		return murmur3.New32(), fmt.Errorf("unknown key hash function: %s. falling back to murmur32", algorithm)
	}
}

func HashStr(in string, withAlg ...string) string {
	var algo string
	if len(withAlg) > 0 && withAlg[0] != "" {
		algo = withAlg[0]
	} else {
		algo = TokenHashAlgo(in)
	}

	h, _ := hashFunction(algo)
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

func HashStr2(in string) string {
	algo.Write([]byte(in))
	return hex.EncodeToString(algo.Sum(nil))
}

func reset() {
	algo.Reset()
}

func HashKey(in string, hashKey bool) string {
	if !hashKey {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}
