/*

Este programa demuestra el uso de clave pública para establecer una clave de sesión y un túnel cifrado
en una arquitectura cliente servidor:
	- intercambio de claves con RSA
	- transmisión de mensajes utilizando encoding (JSON, pero puede ser gob, etc.)

El servidor es concurrente, siendo capaz de manejar múltiples clientes simultáneamente.


*/

package main

import (
	"bufio"
	"strings"
	//"bufio"
	//"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

const (
	directory string = "servidor/"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	fmt.Println("Bienvenido Cliente de clave pública en Go.")
	if len(os.Args) > 2 {
		client(os.Args[1], os.Args[2], "No")
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Seleccione una opción: ")
		fmt.Println(" [1] Registrar usuario")
		fmt.Println(" [2] Login usuario")
		fmt.Println(" [3] Salir")
		scanner.Scan()
		opcion := scanner.Text()
		
			switch opcion {
				case "1": registrar()
				case "2": menu()
				case "3": break;
				default: 
					fmt.Println("Entrada incorrecta")
					break;
			}
		

		
			
		
	}
}


type Pass struct {
	Sal []byte `json:"sal"`
	PasswordSal []byte `json:"passwordSal"`
}

func CreatePass(user string, password string) Pass {
	if user == "" || password == "" {
		log.Fatal("User/Password is null")
	}
	//pUser := new(Pass)
	var pUser Pass
	MakeSal(&pUser.Sal)
	pUser.PasswordSal = createHash(pUser.Sal, []byte(password))
	
	return pUser
}

func StoreUser(user string, pass Pass) {
	var warehouse map[string]Pass
			if _, err := os.Stat(directory + "user.txt"); os.IsNotExist(err) {
				os.Mkdir(directory, 0777)
				os.Create(directory + "user.txt")
				warehouse = make(map[string]Pass)
			}
	
	bytes, err := ioutil.ReadFile(directory + "user.txt")
	if err != nil {
		fmt.Println("no es nil")
		warehouse = make(map[string]Pass)
	}
	json.Unmarshal(bytes, &warehouse)
	warehouse[user] = pass
	bytes, err = json.Marshal(warehouse)
	ioutil.WriteFile(directory + "user.txt", bytes, 0666)
}


func registrar() string {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Introduce tu usuario: ")
	scanner.Scan()
	user := scanner.Text()
	fmt.Print("Introduce tu contraseña: ")
	scanner.Scan()
	pass := scanner.Text()
	//passSt := CreatePass(user, pass)
	//StoreUser(user, passSt)
	client(user,pass,"nuevoUserCrear")
	return user
}

func menu() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Introduce tu usuario: ")
	scanner.Scan()
	cliente := scanner.Text()

	fmt.Println("Introduce tu contraseña: ")
	scanner.Scan()
	password := scanner.Text()
	client(cliente, password, "No")
}

type User struct {
	Name      string
	Pass      string
	Conectado string
	Sal       []byte
	Clave     []byte
}

type Msg struct {
	Usuario string
	Comando string
	Nombre  string
	Destino string
	Datos   []byte
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func Cipher(plain_text []byte, cipher_pass []byte) []byte {
	block, err := aes.NewCipher(cipher_pass)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plain_text))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plain_text)

	return ciphertext
}

/*
Descifra una cadena. Devuelve la cadena descifrada.
*/
func Decipher(ciphertext []byte, cipher_pass []byte) []byte {

	block, err := aes.NewCipher(cipher_pass)
	if err != nil {
		panic(err)
	}

	plain_text := make([]byte, len(ciphertext[aes.BlockSize:]))
	stream := cipher.NewCTR(block, ciphertext[:aes.BlockSize])
	stream.XORKeyStream(plain_text, ciphertext[aes.BlockSize:])

	return plain_text
}

func createHash(sal []byte, pass []byte) []byte {

	tmp := make([]byte, len(sal)+len(pass))

	copy(tmp[:16], sal)
	copy(tmp[16:], pass)

	hasher := sha256.New()
	hasher.Reset()
	_, err := hasher.Write(tmp)
	check(err)

	resume := hasher.Sum(nil)

	return resume
}

func MakeSal(sal *[]byte) {
	*sal = make([]byte, 16)
	_, err := rand.Read(*sal)
	check(err)
}

func client(c string, p string, nuevoUser string) {
	
	cli_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	chk(err)
	cli_keys.Precompute() // aceleramos su uso con un precálculo

	conn, err := net.Dial("tcp", "localhost:1337") // llamamos al servidor
	chk(err)
	defer conn.Close() // es importante cerrar la conexión al finalizar

	fmt.Println("conectado a ", conn.RemoteAddr())

	var srv_pub rsa.PublicKey // contendrá la clave pública del servidor

	je := json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
	jd := json.NewDecoder(conn)

	err = je.Encode(&cli_keys.PublicKey) // envíamos la clave pública del cliente
	chk(err)

	err = jd.Decode(&srv_pub) // recibimos la clave pública del servidor
	chk(err)

	cli_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
	buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
	rand.Read(cli_token)          // generación del token aleatorio para el cliente

	// ciframos el token del cliente con la clave pública del servidor
	enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &srv_pub, cli_token)
	chk(err)

	err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
	chk(err)

	err = jd.Decode(&buff) // leemos el token cifrado procedente del servidor
	chk(err)

	// desciframos el token del servidor con nuestra clave privada
	session_key, err := rsa.DecryptPKCS1v15(rand.Reader, cli_keys, buff)
	chk(err)

	// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
	for i := 0; i < len(cli_token); i++ {
		session_key[i] ^= cli_token[i]
	}

	aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
	chk(err)

	aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
	aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

	// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
	je = json.NewEncoder(aeswr)
	jd = json.NewDecoder(aesrd)
	
	    
	
	je.Encode(&User{Name: c, Pass: p})
	
	if(nuevoUser == "nuevoUserCrear") {	
	  
	  je.Encode(&Msg{Usuario: nuevoUser, Comando: nuevoUser, Nombre: nuevoUser, Destino: nuevoUser})
	  fmt.Println("Usuario creado, haciendo login...\n");
	  
	} else {
	  je.Encode(&Msg{Usuario: nuevoUser, Comando: "nada", Nombre: nuevoUser, Destino: nuevoUser})
	}
	var u User
	jd.Decode(&u)
	
	fmt.Println("Introduzca Comando [up/down/delete/Salir] Nombre fichero  Ruta fichero")
	fmt.Println("Ejemplo : up ejemplo.txt | up ejemplo.txt carpeta/p1 | down ejemplo.txt | delete ejemplo.txt | Salir")

	keyscan := bufio.NewScanner(os.Stdin) // scanner para la entrada estándar (teclado)

	leemos := true
	if u.Conectado == "Ok" {
		for leemos == true { // escaneamos la entrada

			fmt.Println("Introduce Comando : ")
			keyscan.Scan()
			result := strings.Split(keyscan.Text(), " ")

			if len(result) >= 1 && len(result) <= 3 {
				if result[0] == "Salir" || result[0] == "down" || result[0] == "up" || result[0] == "delete" {
					if len(result) == 2 || len(result) == 3 {
						if result[0] == "up" {
							var d []byte
							if len(result) == 2 {
								d, _ = ioutil.ReadFile(result[1])

							} else {
								d, _ = ioutil.ReadFile(result[2] + "/" + result[1])
							}
							clave := []byte(u.Clave)
							fichero := Cipher(d, clave)

							je.Encode(&Msg{Usuario: c, Comando: result[0], Nombre: result[1], Destino: "", Datos: fichero})
						} else {
							je.Encode(&Msg{Usuario: c, Comando: result[0], Nombre: result[1], Destino: ""})
						}
					} else {
						je.Encode(&Msg{Usuario: c, Comando: "Salir", Nombre: ""})
						break
					}
					var m Msg
					jd.Decode(&m)
					if m.Comando == "down" {
						clave := []byte(u.Clave)
						if m.Datos != nil {
							datos := Decipher(m.Datos, clave)
							os.Create("Cliente/" + m.Nombre)
							ioutil.WriteFile("Cliente/"+m.Nombre, datos, 0777)
							fmt.Println("Descargado fichero")
						} else {
							fmt.Println("Fichero seleccionado no existe")
						}
					}
					je.Encode(&Msg{Usuario: c, Comando: "", Nombre: ""})
					jd.Decode(&m)
				} else {
					fmt.Println("Comando Incorrecto.Introduzca up/down/delete/Salir")
				}
			} else {
				leemos = true
			}

		}
	} else if u.Conectado == "No" {
		keyscan := bufio.NewScanner(os.Stdin)
		fmt.Println("Usuario o Contraseña Incorrecto")
		fmt.Println("¿Desea Salir? s/n")
		keyscan.Scan()
		op := keyscan.Text()
		if op != "s" {
			menu()
		}

	}
}
