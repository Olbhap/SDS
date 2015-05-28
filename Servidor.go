/*

Este programa demuestra el uso de clave pública para establecer una clave de sesión y un túnel cifrado
en una arquitectura cliente servidor:
	- intercambio de claves con RSA
	- transmisión de mensajes utilizando encoding (JSON, pero puede ser gob, etc.)

El servidor es concurrente, siendo capaz de manejar múltiples clientes simultáneamente.

ejemplos de uso:

go run pub.go srv

go run pub.go cli

*/

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

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
}

type User struct {
	Name string
	Pass string
}

func listar() {
	files, _ := ioutil.ReadDir("./")
	for _, f := range files {
		fmt.Println(f.Name())
	}
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
			fmt.Println(u)
			var existeuser bool = false

			if _, err := os.Stat("servidor/user.txt"); os.IsNotExist(err) {
				os.Mkdir("servidor/", 0777)
				os.Create("servidor/user.txt")
				ejemplo := []byte("admin 1234 \n")
				ioutil.WriteFile("servidor/user.txt", ejemplo, 0644)
			}

			file, err := os.Open("servidor/user.txt")

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			defer file.Close()

			reader := bufio.NewReader(file)
			scanner := bufio.NewScanner(reader)

			for scanner.Scan() {
				result := strings.Split(scanner.Text(), " ")
				fmt.Println(result[1])
				if u.Name == result[0] && u.Pass == result[1] {
					existeuser = true
					break
				}
			}

			if existeuser == true {
				je.Encode(&User{Name: "Servidor", Pass: "Ok"})

			} else {
				je.Encode(&User{Name: "Servidor", Pass: "No"})
			}

			if existeuser == true {
				for i != "Salir" {
					var d []byte
					var m Msg
					jd.Decode(&m)
					fmt.Println(m)
					i = m.Comando

					if Comprobar(m) == true {
						cont = 0
						if _, err := os.Stat("servidor/" + m.Usuario); os.IsNotExist(err) {
							os.Mkdir("servidor/"+m.Usuario+"/", 0777)
							os.Mkdir("Cliente/", 0777)
						}

						listar()
						if m.Comando == "up" {
							os.Create("servidor/" + m.Usuario + "/" + m.Nombre)
							ioutil.WriteFile("servidor/"+m.Usuario+"/"+m.Nombre, m.Datos, 0777)

						} else if m.Comando == "delete" {
							os.Remove("servidor/" + m.Usuario + "/" + m.Nombre)

						} else if m.Comando == "down" {
							e, _ := ioutil.ReadFile("servidor/" + m.Usuario + "/" + m.Nombre)
							d = e
						}
						je.Encode(&Msg{Usuario: "Servidor", Comando: m.Comando, Nombre: m.Nombre, Datos: d})

					} else {
						cont = cont + 1
						cliente_msg = "Comando o Tipo incorrecto por favor introduzca Comando [up/down/delete/Salir]"
						fmt.Println("entra")
						if cont == 3 {
							break
						}
					}
					je.Encode(&Msg{Usuario: "Servidor ", Comando: cliente_msg, Nombre: "dos"})
					jd.Decode(&m)
					fmt.Println(m.Usuario)
				}
			}
			conn.Close() // cerramos la conexión
			fmt.Println("cierre[", port, "]")

		}()
	}
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
	case "Salir":
	default:
		fmt.Println("Comando incorrecto por favor introduzca up/down/delete")
		comprobar = false
	}

	return comprobar
}
