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
	"archive/tar"
	"bufio"
	//"compress/gzip"
	//"compress/flate"
	//"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	//"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
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
				os.Create("servidor/user.txt")
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

					fmt.Println("existe")
					break
				}

			}

			if existeuser == true {
				je.Encode(&User{Name: "Servidor", Pass: "Ok"})

			} else {
				je.Encode(&User{Name: "Servidor", Pass: "No"})

			}

			for i != "Salir" {
				var d []byte
				//je.Encode(&Msg{Usuario: "Servidor", Comando: cliente_msg, Tipo: "casa", Nombre: "pata"})
				var m Msg
				jd.Decode(&m)
				fmt.Println(m)
				i = m.Comando

				if Comprobar(m) == true {
					cont = 0
					cliente_msg = ""
					if m.Tipo == "f" {
						sourceinfo, err := os.Stat(m.Nombre)
						if err == nil {
							err = os.MkdirAll("servidor/"+m.Usuario, sourceinfo.Mode())
							err = os.MkdirAll("Cliente/", sourceinfo.Mode())
							if err != nil {
								fmt.Println(err)

							}
						}

						listar()
						if m.Comando == "up" {
							/*if m.Destino == "" {
								CopyFile(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
							} else {
								CopyFile(m.Destino+"/"+m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
							}*/
							os.Create("servidor/" + m.Usuario + "/" + m.Nombre)
							ioutil.WriteFile("servidor/"+m.Usuario+"/"+m.Nombre, m.Datos, 0777)
							//je.Encode(&Msg{Usuario: "Servidor", Comando: cliente_msg, Tipo: "casa", Nombre: "pata"})
						} else if m.Comando == "delete" {
							if m.Destino == "" {
								os.Remove("servidor/" + m.Usuario + "/" + m.Nombre)
							} else {
								os.Remove("servidor/" + m.Usuario + "/" + m.Destino + "/" + m.Nombre)
							}
							//je.Encode(&Msg{Usuario: "Servidor", Comando: cliente_msg, Tipo: "casa", Nombre: "pata"})

						} else if m.Comando == "down" {
							/*if m.Destino == "" {
								CopyFile("servidor/"+m.Usuario+"/"+m.Nombre, "Cliente/"+m.Nombre)
							} else {
								CopyFile("servidor/"+m.Usuario+"/"+m.Destino+"/"+m.Nombre, "Cliente/"+m.Nombre)
							}*/
							e, _ := ioutil.ReadFile("servidor/" + m.Usuario + "/" + m.Nombre)
							d = e
						}
						je.Encode(&Msg{Usuario: "Servidor", Comando: m.Comando, Tipo: cliente_msg, Nombre: m.Nombre, Datos: d})
					} /*else if m.Tipo == "d" {
						listar()
						if m.Comando == "up" {
							if m.Destino == "" {
								CopyDir(m.Nombre, "servidor/"+m.Usuario+"/"+m.Nombre)
							} else {
								CopyDir(m.Destino+"/"+m.Nombre, "servidor/"+m.Usuario+"/"+m.Destino+"/"+m.Nombre)
							}

						} else if m.Comando == "delete" {
							if m.Destino == "" {
								os.RemoveAll("servidor/" + m.Usuario + "/" + m.Nombre)
							} else {
								os.RemoveAll("servidor/" + m.Usuario + "/" + m.Destino + "/" + m.Nombre)
							}

						} else if m.Comando == "down" {
							if m.Destino == "" {
								comprimir(m)
								CopyFile("servidor/"+m.Usuario+"/"+m.Nombre+".tar.gz", "Cliente/"+m.Nombre+".tar.gz")
								os.Remove("servidor/" + m.Usuario + "/" + m.Nombre + ".tar.gz")
							} else {
								comprimir(m)
								CopyFile("servidor/"+m.Usuario+"/"+m.Destino+"/"+m.Nombre+".tar.gz", "Cliente/"+m.Nombre+".tar.gz")
								os.Remove("servidor/" + m.Usuario + "/" + m.Destino + "/" + m.Nombre + ".tar.gz")
							}
						}
					}*/
				} else {
					cont = cont + 1
					cliente_msg = "Comando o Tipo incorrecto por favor introduzca Comando [up/down/delete/Salir]  o  Tipo[f/d]"
					fmt.Println("entra")
					if cont == 3 {
						break

					}
				}
				je.Encode(&Msg{Usuario: "Servidor ", Comando: cliente_msg, Tipo: "uno", Nombre: "dos"})
				jd.Decode(&m)
				fmt.Println(m.Usuario)
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

func comprimir(nombre Msg) {
	var destinationfile string = ""
	if nombre.Destino == "" {
		destinationfile = "servidor/" + nombre.Usuario + "/" + nombre.Nombre + ".tar.gz"
	} else {
		destinationfile = "servidor/" + nombre.Usuario + "/" + nombre.Destino + "/" + nombre.Nombre + ".tar.gz"

	}

	if destinationfile == "" {
		fmt.Println("No existe destino")
		os.Exit(1)
	}
	var sourcedir string = ""
	if nombre.Destino == "" {
		sourcedir = "servidor/" + nombre.Usuario + "/" + nombre.Nombre
	} else {
		sourcedir = "servidor/" + nombre.Usuario + "/" + nombre.Destino + "/" + nombre.Nombre

	}

	if sourcedir == "" {
		fmt.Println("No existe origen")
		os.Exit(1)
	}

	dir, err := os.Open(sourcedir)

	checkerror(err)

	defer dir.Close()

	files, err := dir.Readdir(0)

	checkerror(err)

	tarfile, err := os.Create(destinationfile)

	checkerror(err)

	defer tarfile.Close()
	var fileWriter io.WriteCloser = tarfile

	if strings.HasSuffix(destinationfile, ".gz") {
		fileWriter = gzip.NewWriter(tarfile) // add a gzip filter
		defer fileWriter.Close()             // if user add .gz in the destination filename
	}

	tarfileWriter := tar.NewWriter(fileWriter)
	defer tarfileWriter.Close()

	for _, fileInfo := range files {
		if fileInfo.IsDir() {
			fmt.Println(fileInfo.Name())
			continue
		}
		var ruta string = ""
		if nombre.Destino == "" {
			ruta = "."
		} else {
			ruta = nombre.Destino
		}

		file, err := os.Open(ruta + "/" + nombre.Nombre + string(filepath.Separator) + fileInfo.Name())

		checkerror(err)

		defer file.Close()

		// prepare the tar header

		header := new(tar.Header)
		header.Name = file.Name()
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarfileWriter.WriteHeader(header)

		checkerror(err)

		_, err = io.Copy(tarfileWriter, file)

		checkerror(err)
	}

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
	case "Salir":
	default:
		fmt.Println("Comando incorrecto por favor introduzca up/down/delete")
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

		//fmt.Print("1 ")

		fmt.Println(err)
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {

		//fmt.Print("2 ")

		fmt.Println(err)
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)
		if err != nil {

			err = os.Chmod(dest, sourceinfo.Mode())

			//fmt.Print("3 ")

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
