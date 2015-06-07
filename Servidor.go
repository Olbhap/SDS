/*

Este programa demuestra el uso de clave pública para establecer una clave de sesión y un túnel cifrado
en una arquitectura cliente servidor:
	- intercambio de claves con RSA
	- transmisión de mensajes utilizando encoding (JSON, pero puede ser gob, etc.)

El servidor es concurrente, siendo capaz de manejar múltiples clientes simultáneamente.

*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

const (
	directory string = "servidor/"
)

func main() {

	fmt.Println("Servidor de clave pública en Go.")
	fmt.Println("Modo Servidor Activado ...")
	server()
}

type Msg struct {
	Usuario string
	Comando string
	Nombre  string
	Destino string
	Datos   []byte
	Clave   []byte
}

type User struct {
	Name      string
	Pass      string
	Sal       []byte
	Conectado string
	Clave     []byte
	newUser string
}

type Pass struct {
	Sal []byte `json:"sal"`
	PasswordSal []byte `json:"passwordSal"`
}

func listar(user string) string{
	files, _ := ioutil.ReadDir(directory+user)
	var lista string
	for _, f := range files {
		lista=lista +" "+ f.Name()
	}
	return lista
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
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

func CreatePass(user string, password string) Pass {
	if user == "" || password == "" {
		log.Fatal("User/Password is null")
	}
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

// gestiona el modo servidor
func server() {

	srv_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	chk(err)
	srv_keys.Precompute() // aceleramos su uso con un precálculo

	ln, err := net.Listen("tcp", "localhost:1337") // escucha en espera de conexión
	chk(err)
	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	for { // búcle infinito, se sale con ctrl+c
		conn, err := ln.Accept() // para cada nueva petición de conexión
		chk(err)
		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			chk(err)

			fmt.Println("conexión: ", conn.LocalAddr(), " <--> ", conn.RemoteAddr())

			var cli_pub rsa.PublicKey // contendrá la clave pública del cliente

			je := json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
			jd := json.NewDecoder(conn)

			err = je.Encode(&srv_keys.PublicKey) // envíamos la clave pública del servidor
			chk(err)

			err = jd.Decode(&cli_pub) // recibimos la clave pública del cliente
			chk(err)

			srv_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
			buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
			rand.Read(srv_token)          // generación del token aleatorio para el servidor

			// ciframos el token del servidor con la clave pública del cliente
			enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &cli_pub, srv_token)
			chk(err)

			err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
			chk(err)

			err = jd.Decode(&buff) // leemos el token cifrado procedente del cliente
			chk(err)

			// desciframos el token del cliente con nuestra clave privada
			session_key, err := rsa.DecryptPKCS1v15(rand.Reader, srv_keys, buff)
			chk(err)

			// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
			for i := 0; i < len(srv_token); i++ {
				session_key[i] ^= srv_token[i]
			}

			aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
			chk(err)

			aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
			aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

			// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
			je = json.NewEncoder(aeswr)
			jd = json.NewDecoder(aesrd)		

			var i string = ""
			var cont int = 0
			var cliente_msg string = ""

			var u User
			jd.Decode(&u)
			
			
			var meme Msg
			jd.Decode(&meme)
			
			
			if(meme.Comando=="nuevoUserCrear") {
			  fmt.Println("Creando nuevo usuario...")
			  passSt := CreatePass(u.Name, u.Pass)
			  StoreUser(u.Name, passSt)			  
			}
						  
			var existeuser bool = false

			file, err := os.Open(directory + "user.txt")

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			defer file.Close()			
			
			passSaltGen := GetUser(u.Name, u.Pass)
			if( passSaltGen != nil) {
				existeuser = true			
			}else {
				existeuser = false
			}

			if(existeuser) {
				je.Encode(&User{Name: "Servidor", Clave: passSaltGen, Conectado: "Ok"})
			}else {
				je.Encode(&User{Name: "Servidor", Conectado: "No"})
			}
			
			if existeuser == true {
				for i != "Salir" {
					var d []byte
					var m Msg
					var lista string=""
					jd.Decode(&m)
					i = m.Comando

					if Comprobar(m) == true {
						cont = 0
						if _, err := os.Stat(directory + m.Usuario); os.IsNotExist(err) {
							os.Mkdir(directory+m.Usuario+"/", 0777)
							os.Mkdir("Cliente/", 0777)
						}

						listar(m.Usuario)
						if m.Comando == "up" {
							if(m.Nombre != "error_subida_fichero") {
								os.Create(directory + m.Usuario + "/" + m.Nombre)
								ioutil.WriteFile(directory+m.Usuario+"/"+m.Nombre, m.Datos, 0777)
							}

						} else if m.Comando == "delete" {
							os.Remove(directory + m.Usuario + "/" + m.Nombre)

						} else if m.Comando == "down" {
							if _, err := os.Stat(directory + m.Usuario + "/" + m.Nombre); os.IsNotExist(err) {

							} else {
								e, _ := ioutil.ReadFile(directory + m.Usuario + "/" + m.Nombre)
								d = e
							}
						}else if m.Comando == "listar" {
							lista=listar(m.Usuario)
						}
						je.Encode(&Msg{Usuario: "Servidor", Comando: m.Comando, Nombre: m.Nombre, Datos: d,Destino:lista})

					} else {
						cont = cont + 1
						cliente_msg = "Comando o Tipo incorrecto por favor introduzca Comando [up/down/delete/Salir]"
						if cont == 3 {
							break
						}
					}
					je.Encode(&Msg{Usuario: "Servidor ", Comando: cliente_msg, Nombre: "dos"})
					jd.Decode(&m)
				}
			}
			conn.Close() // cerramos la conexión
			fmt.Println("cierre[", port, "]")

		}()
		
	}
}


func GetUser(user string, password string) []byte {
	var warehouse map[string]Pass
	if _, err := os.Stat(directory + "user.txt"); os.IsNotExist(err) {
				os.Mkdir(directory, 0777)
				os.Create(directory + "user.txt")
				warehouse = make(map[string]Pass)
	}
	
	bytes, err := ioutil.ReadFile(directory + "user.txt")
	if err != nil {
		return nil
	}
	json.Unmarshal(bytes, &warehouse)
	// comprueba si un usuario existe
	data := warehouse[user]
	if data.Sal == nil {
		return nil
	}
	// Get password+sal generated
	var passSaltGen = createHash(data.Sal, []byte(password))
	if string(passSaltGen) == string(data.PasswordSal) {		
		return passSaltGen
	} else {
		
		return nil
	}
}
//Devuelve la contraseña del usuario indicado.
func GetPassword(user string) []byte {
	var warehouse map[string]Pass
	bytes, err := ioutil.ReadFile(directory + "user.txt")
	if err != nil {
		log.Fatal("The file does not exist")
	}
	json.Unmarshal(bytes, &warehouse)
	return warehouse[user].PasswordSal
}

func checkerror(err error) {

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func Comprobar(mensaje Msg) bool {
	var comprobar = true
	switch mensaje.Comando {
	case "up":
		comprobar = true
	case "down":
		comprobar = true
	case "delete":
		comprobar = true
			case "listar":
		comprobar = true
	case "Salir":
	default:
		fmt.Println("Comando incorrecto por favor introduzca up/down/delete")
		comprobar = false
	}

	return comprobar
}
