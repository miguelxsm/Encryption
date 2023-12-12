import os
import subprocess
import glob
import re

def ejecutar_programa(archivo_original, archivo_temporal, programa_cpp):
    # Renombrar el archivo a "entrada.txt"
    os.rename(archivo_original, archivo_temporal)

    with open(archivo_temporal, 'r', encoding='utf-8') as file:
        # Leer todo el contenido del archivo
        contenido = file.read()

        # Buscar la URL de YouTube en las primeras dos líneas
        primeras_lineas = contenido.splitlines()[:2]
        link_video = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', "".join(primeras_lineas))
        link_video = link_video.group(0) if link_video else "No link found"

        # Contar la cantidad total de caracteres en el archivo
        caracteres = len(contenido)

    # Ejecutar el programa en C++ y capturar la salida estándar
    resultado = subprocess.run([programa_cpp, archivo_temporal], capture_output=True, text=True)
    salida = resultado.stdout

    # Restaurar el nombre original del archivo
    os.rename(archivo_temporal, archivo_original)

    # Extraer los tiempos de la salida
    tiempos = re.findall(r"(\w[\w\s]*): (\d+\.\d+) ms", salida)
    tiempo_rsa = next((t for n, t in tiempos if "RSA" in n), "N/A")
    tiempo_ecc = next((t for n, t in tiempos if "ECC" in n), "N/A")

    return link_video, caracteres, tiempo_rsa, tiempo_ecc

def main():
    programa_cpp = "./encriptar"  # Reemplazar con el nombre del ejecutable de tu programa C++
    archivo_temporal = "entrada.txt"

    with open("info_videos.txt", "w", encoding='utf-8') as info_file:
        for archivo_original in glob.glob("*.txt"):
            if archivo_original == "info_videos.txt" or archivo_original == "salida.txt":
                continue
            link_video, caracteres, tiempo_rsa, tiempo_ecc = ejecutar_programa(archivo_original, archivo_temporal, programa_cpp)
            info_file.write(f"{link_video} {caracteres} {tiempo_rsa} {tiempo_ecc}\n")

if __name__ == "__main__":
    main()
