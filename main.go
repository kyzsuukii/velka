package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Host string `yaml:"host"`
	User string `yaml:"user"`
	Port int    `yaml:"port,omitempty"`
}

type UserConfig struct {
	Servers []string `yaml:"servers"`
}

type Servers map[string]ServerConfig
type Users map[string]UserConfig

func readServerConfig(filename string) (Servers, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var servers Servers
	err = yaml.Unmarshal(data, &servers)
	if err != nil {
		return nil, err
	}

	for name, server := range servers {
		if server.Port == 0 {
			server.Port = 22
			servers[name] = server
		}
	}

	return servers, nil
}

func readUserConfig(filename string) (Users, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var users Users
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func readPublicKeys(dir string) (map[string]string, error) {
	keys := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pub") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			keys[info.Name()] = string(data)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}

func readPrivateKey(filename string, passphrase []byte) (ssh.Signer, error) {
	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var privateKey ssh.Signer
	if len(passphrase) > 0 {
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, passphrase)
	} else {
		privateKey, err = ssh.ParsePrivateKey(privateKeyBytes)
	}
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func createSSHConfig(privateKey ssh.Signer) (*ssh.ClientConfig, error) {
	return &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func updateServerKeys(server ServerConfig, publickey string, config *ssh.ClientConfig, username string, allUsers []string) error {
	config.User = server.User
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", server.Host, server.Port), config)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf(`
        AUTHKEYS=~/.ssh/authorized_keys
        PUBKEY="%s"
        USERNAME="%s"
        DATETIME=$(date "+%%Y-%%m-%%d %%H:%%M:%%S")
        if ! grep -Fxq "$PUBKEY" "$AUTHKEYS"; then
            mkdir -p ~/.ssh
            echo -e "\n# Public key for user $USERNAME (Added: $DATETIME)\n$PUBKEY" >> "$AUTHKEYS"
            sed -i -e '/^$/N;/^\n$/D' "$AUTHKEYS"
        fi

        CURRENT_USERS="%s"
        sed -i.bak '/^# Public key for user/!b;:a;/^\n*$/!{N;ba};/^\n*$/d' "$AUTHKEYS"
        while read -r line; do
            if [[ $line == "# Public key for user"* ]]; then
                user=$(echo "$line" | awk '{print $6}')
                if ! echo "$CURRENT_USERS" | grep -q "$user"; then
                    sed -i "/# Public key for user $user/,+2d" "$AUTHKEYS"
                fi
            fi
        done < "$AUTHKEYS"
    `, strings.TrimSpace(publickey), username, strings.Join(allUsers, " "))

	err = session.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to run command: %v", err)
	}

	return nil
}

func main() {
	servers, err := readServerConfig("./etc/servers.yaml")
	if err != nil {
		log.Fatalf("Error reading server config: %v", err)
	}
	users, err := readUserConfig("./etc/users.yaml")
	if err != nil {
		log.Fatalf("Error reading user config: %v", err)
	}
	keys, err := readPublicKeys("./public_keys")
	if err != nil {
		log.Fatalf("Error reading public keys: %v", err)
	}

	passphrase := []byte(os.Getenv("PRIVATE_KEY_PASSWORD"))
	privateKey, err := readPrivateKey("./etc/ssh/id_rsa", passphrase)
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	config, err := createSSHConfig(privateKey)
	if err != nil {
		log.Fatalf("Error creating SSH config: %v", err)
	}
	allUsers := make([]string, 0, len(users))
	for user := range users {
		allUsers = append(allUsers, user)
	}

	for user, userConfig := range users {
		publicKey, ok := keys[user+".pub"]
		if !ok {
			log.Printf("Warning: No public key found for user %s", user)
			continue
		}

		for _, serverName := range userConfig.Servers {
			if serverName == "*" {
				for _, server := range servers {
					err := updateServerKeys(server, publicKey, config, user, allUsers)
					if err != nil {
						log.Printf("Error updating keys for user %s on server %s: %v", user, server.Host, err)
					}
				}
			} else {
				server, ok := servers[serverName]
				if !ok {
					log.Printf("Warning: Server %s not found in configuration", serverName)
					continue
				}
				err := updateServerKeys(server, publicKey, config, user, allUsers)
				if err != nil {
					log.Printf("Error updating keys for user %s on server %s: %v", user, server.Host, err)
				}
			}
		}
	}
}
