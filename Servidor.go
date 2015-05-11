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
	//"bufio"

	"bufio"
	//"compress/flate"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
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

// Mensaje genérico con un identificador y un argumento asociado
/*type Msg struct {
	Id  string
	Arg interface{}
}*/
type Msg struct {
	Usuario string
	Comando string
	Tipo    string
	Nombre  string
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
			for i != "Salir" {
				// envíamos un mensaje de HELLO (ejemplo)
				je.Encode(&Msg{Usuario: "Servidor", Comando: "", Tipo: "t", Nombre: "./ej"})

				// leemos el mensaje de HELLO del cliente y lo imprimimos
				var m Msg
				jd.Decode(&m)
				fmt.Println(m)
				i = m.Nombre
				if Comprobar(m) == true {
					if m.Tipo == "f" {
						sourceinfo, err := os.Stat(m.Nombre)
						if err == nil {
							fmt.Println("pe2")

							err = os.MkdirAll("servidor/"+m.Usuario, sourceinfo.Mode())
							if err != nil {
								fmt.Println("pe3")
								fmt.Println(err)

							}

							//CopyDir(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
							listar()
							if m.Comando == "up" {

								CopyFile(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
							} else if m.Comando == "delete" {
								os.Remove("servidor/" + m.Usuario + "/" + m.Nombre)
							} else {
								Comprimir("servidor/" + m.Usuario + "/" + m.Nombre)

								CopyFile("servidor/"+m.Usuario+"/"+m.Nombre+".gz", m.Nombre+".gz")
								os.Remove("servidor/" + m.Usuario + "/" + m.Nombre + ".gz")
							}
						}
					} else {
						listar()
						if m.Comando == "up" {

							CopyDir(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
						} else if m.Comando == "delete" {
							//os.RemoveAll("servidor/" + m.Usuario + "/" + m.Nombre)
						} else {
							//Comprimir("servidor/" + m.Usuario + "/" + m.Nombre)

							CopyDir("servidor/"+m.Usuario+"/"+m.Nombre, m.Nombre)
							//os.Remove("servidor/" + m.Usuario + "/" + m.Nombre + ".gz")
						}

					}
				}
				//CopyFile(m.Id, "output.txt")
				//CopyDir(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
				je.Encode(&Msg{Usuario: "TESTServidor", Comando: "pruebaServidor", Tipo: "t", Nombre: ""})
				jd.Decode(&m)
				fmt.Println(m.Usuario)

				//CopyFile("input.txt", "output.txt")
				//CopyDir(scanner.Text(),"servidor/"+port+"/"+scanner.Text())

			}

			conn.Close() // cerramos la conexión
			fmt.Println("cierre[", port, "]")

		}()
	}
}

func Comprimir(nombre string) bool {
	flag.Parse() // get the arguments from command line

	filename := nombre

	if filename == "" {
		fmt.Println("Usage : go-gzip sourcefile")
		os.Exit(1)
	}

	rawfile, err := os.Open(filename)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rawfile.Close()

	// calculate the buffer size for rawfile
	info, _ := rawfile.Stat()

	var size int64 = info.Size()
	rawbytes := make([]byte, size)

	// read rawfile content into buffer
	buffer := bufio.NewReader(rawfile)
	_, err = buffer.Read(rawbytes)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	writer.Write(rawbytes)
	writer.Close()

	err = ioutil.WriteFile(filename+".gz", buf.Bytes(), info.Mode())
	// use 0666 to replace info.Mode() if you prefer

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%s compressed to %s\n", filename, filename+".gz")
	return true
}

func Comprobar(mensaje Msg) bool {
	var comprobar = true
	switch mensaje.Comando {
	case "up":
		comprobar = ComprobarTipo(mensaje)
	case "down":
		comprobar = ComprobarTipo(mensaje)
	case "delete":
		comprobar = ComprobarTipo(mensaje)
	default:
		fmt.Println("Comando incorrecto por favor introduzca up/down")
		comprobar = false
	}

	return comprobar
}
func ComprobarTipo(mensaje Msg) bool {
	var comprobar = true
	switch mensaje.Tipo {
	case "f":
		comprobar = true
	case "d":
		comprobar = true
	default:
		fmt.Println("Tipo incorrecto por favor introduzca f/d")
		comprobar = false
	}

	return comprobar
}

//Copia ficheros crea el fichero destino
func CopyFile(source string, dest string) (err error) {
	fmt.Println("Copiando fichero...")
	sourcefile, err := os.Open(source)
	if err != nil {
		fmt.Print("1 ")
		fmt.Println(err)
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {
		fmt.Print("2 ")
		fmt.Println(err)
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)
		if err != nil {

			err = os.Chmod(dest, sourceinfo.Mode())
			fmt.Print("3 ")
			fmt.Println(err)
		}

	}

	return
}

//Copia todo el contenido de la carpeta indicada incluso las carpetas que hay dentro
func CopyDir(source string, dest string) (err error) {

	fmt.Println("Copiando directorio..." + source + " - " + dest)
	sourceinfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dest, sourceinfo.Mode())
	if err != nil {
		return err
	}

	directory, _ := os.Open(source)

	objects, err := directory.Readdir(-1)

	for _, obj := range objects {

		sourcefilepointer := source + "/" + obj.Name()

		destinationfilepointer := dest + "/" + obj.Name()

		if obj.IsDir() {

			err = CopyDir(sourcefilepointer, destinationfilepointer)
			if err != nil {
				fmt.Println(err)
			}
		} else {

			err = CopyFile(sourcefilepointer, destinationfilepointer)
			if err != nil {
				fmt.Println(err)
			}
		}

	}
	return
}
