package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"

	"crypto/ecdsa"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/mr-tron/base58"
)

const (
	defaultThreads  = 1
	defaultMatches  = 4
	defaultPrintFreq = 100000
)

var regexList []*regexp.Regexp

func generateWallet() (b5, pk string) {
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	address = "41" + address[2:]
	addb, _ := hex.DecodeString(address)
	firstHash := sha256.Sum256(addb)
	secondHash := sha256.Sum256(firstHash[:])
	secret := secondHash[:4]
	addb = append(addb, secret...)
	return base58.Encode(addb), hexutil.Encode(privateKeyBytes)[2:]
}

func matchAddress(address string) bool {
	if len(regexList) == 0 {
		return true
	}

	for _, re := range regexList {
		if re.MatchString(address) {
			return true
		}
	}
	return false
}

func worker(wg *sync.WaitGroup, printFreq int, matchCount *int) {
	defer wg.Done()

	for {
		address, privateKey := generateWallet()
		if matchAddress(address) {
			fmt.Printf("Matched Wallet: Address = %s, PrivateKey = %s\n", address, privateKey)
			writeToFile(address, privateKey)
		}

		*matchCount++
		if *matchCount%printFreq == 0 {
			fmt.Printf("Generated %d wallets\n", *matchCount)
		}
	}
}

func writeToFile(address, privateKey string) {
	file, err := os.OpenFile("data/wallet.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Address: %s, PrivateKey: %s\n", address, privateKey))
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}
}

func main() {
	app := &cli.App{
		Name:  "tron-wallet-generator",
		Usage: "Generate TRON wallets with a specific tail pattern",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "threads",
				Aliases: []string{"t"},
				Value:   defaultThreads,
				Usage:   "Number of threads to use",
			},
			&cli.IntFlag{
				Name:    "matches",
				Aliases: []string{"n"},
				Value:   defaultMatches,
				Usage:   "Number of matching tail digits",
			},
			&cli.IntFlag{
				Name:    "print",
				Aliases: []string{"d"},
				Value:   defaultPrintFreq,
				Usage:   "Frequency of progress printing",
			},
		},
		Action: func(c *cli.Context) error {
			threads := c.Int("threads")
			matches := c.Int("matches")
			printFreq := c.Int("print")

			if matches < 0 {
				return fmt.Errorf("matches should be positive")
			}

			// Update regexList with the new matches
			regexList = nil
			numList := []int{5, 6, 8, 9}
			if matches > 0 {
				for _, num := range numList {
					re, err := regexp.Compile(fmt.Sprintf("(%d){%d}$", num, matches))
					if err != nil {
						return fmt.Errorf("failed to compile regex: %v", err)
					}
					regexList = append(regexList, re)
				}
			}
			

			var wg sync.WaitGroup
			var matchCount int

			for i := 0; i < threads; i++ {
				wg.Add(1)
				go worker(&wg, printFreq, &matchCount)
			}

			wg.Wait()
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

