#!/usr/bin/env python3
"""
exif_metadata.py

Extrae metadatos EXIF de una imagen (marca, modelo, coordenadas GPS,
fecha/hora de captura) y calcula los hashes MD5 y SHA-256 del archivo
para fines de análisis forense / cadena de custodia.

Uso:
    python3 exif_metadata.py /ruta/a/la/imagen.jpg
    python3 exif_metadata.py /ruta/a/la/imagen.jpg --json

Dependencias:
    pip install Pillow --break-system-packages
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    sys.exit(
        "Error: falta la librería Pillow.\n"
        "Instálala con: pip install Pillow --break-system-packages"
    )


def calcular_hashes(ruta_imagen: Path) -> dict:
    """Calcula MD5 y SHA-256 del archivo, leyéndolo por bloques
    para no cargarlo completo en memoria (útil con imágenes grandes)."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(ruta_imagen, "rb") as f:
        for bloque in iter(lambda: f.read(8192), b""):
            md5.update(bloque)
            sha256.update(bloque)

    return {
        "MD5": md5.hexdigest(),
        "SHA256": sha256.hexdigest(),
    }


def _convertir_a_grados(valor) -> float:
    """Convierte una coordenada EXIF en formato ((g,1),(m,1),(s,100)) a
    grados decimales."""
    grados, minutos, segundos = valor
    return float(grados) + float(minutos) / 60.0 + float(segundos) / 3600.0


def extraer_gps(gps_info: dict):
    """Devuelve (latitud, longitud) en grados decimales con signo,
    o None si no hay datos GPS válidos."""
    if not gps_info:
        return None

    gps_data = {}
    for key, val in gps_info.items():
        nombre = GPSTAGS.get(key, key)
        gps_data[nombre] = val

    lat_ref = gps_data.get("GPSLatitudeRef")
    lat = gps_data.get("GPSLatitude")
    lon_ref = gps_data.get("GPSLongitudeRef")
    lon = gps_data.get("GPSLongitude")

    if not (lat and lon and lat_ref and lon_ref):
        return None

    latitud = _convertir_a_grados(lat)
    if lat_ref in ("S", "s"):
        latitud = -latitud

    longitud = _convertir_a_grados(lon)
    if lon_ref in ("W", "w"):
        longitud = -longitud

    return {"latitud": round(latitud, 6), "longitud": round(longitud, 6)}


def extraer_exif(ruta_imagen: Path) -> dict:
    """Extrae marca, modelo, fecha/hora y GPS de los metadatos EXIF."""
    datos = {
        "marca": None,
        "modelo": None,
        "fecha_hora": None,
        "gps": None,
    }

    try:
        with Image.open(ruta_imagen) as img:
            exif_raw = img.getexif()
            if not exif_raw:
                return datos

            exif = {}
            gps_info = {}
            for tag_id, valor in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    # GPSInfo es un IFD anidado, hay que resolverlo aparte
                    gps_info = exif_raw.get_ifd(tag_id)
                elif tag == "ExifOffset":
                    # Los tags de captura (DateTimeOriginal, etc.) viven en
                    # el sub-IFD "Exif", hay que resolverlo aparte también
                    exif_ifd = exif_raw.get_ifd(tag_id)
                    for sub_tag_id, sub_valor in exif_ifd.items():
                        sub_tag = TAGS.get(sub_tag_id, sub_tag_id)
                        exif[sub_tag] = sub_valor
                else:
                    exif[tag] = valor

            datos["marca"] = exif.get("Make")
            datos["modelo"] = exif.get("Model")
            datos["fecha_hora"] = exif.get("DateTimeOriginal") or exif.get(
                "DateTime"
            )
            datos["gps"] = extraer_gps(gps_info)

    except Exception as e:
        datos["error"] = f"No se pudieron leer los EXIF: {e}"

    return datos


def main():
    parser = argparse.ArgumentParser(
        description="Extrae metadatos EXIF y hashes SHA-1/SHA-256 de una imagen."
    )
    parser.add_argument("ruta", help="Ruta al archivo de imagen")
    parser.add_argument(
        "--json", action="store_true", help="Muestra el resultado en formato JSON"
    )
    args = parser.parse_args()

    ruta_imagen = Path(args.ruta)
    if not ruta_imagen.is_file():
        sys.exit(f"Error: no se encontró el archivo '{ruta_imagen}'")

    resultado = {
        "archivo": str(ruta_imagen.resolve()),
        "tamano_bytes": ruta_imagen.stat().st_size,
        "analizado_en": datetime.now().isoformat(timespec="seconds"),
        "exif": extraer_exif(ruta_imagen),
        "hashes": calcular_hashes(ruta_imagen),
    }

    if args.json:
        print(json.dumps(resultado, indent=2, ensure_ascii=False, default=str))
        return

    exif = resultado["exif"]
    print("=" * 60)
    print(f"Archivo:        {resultado['archivo']}")
    print(f"Tamaño:         {resultado['tamano_bytes']} bytes")
    print(f"Analizado:      {resultado['analizado_en']}")
    print("-" * 60)
    print("METADATOS EXIF")
    print(f"  Marca:        {exif.get('marca') or 'No disponible'}")
    print(f"  Modelo:       {exif.get('modelo') or 'No disponible'}")
    print(f"  Fecha/Hora:   {exif.get('fecha_hora') or 'No disponible'}")
    if exif.get("gps"):
        print(
            f"  GPS:          lat {exif['gps']['latitud']}, "
            f"lon {exif['gps']['longitud']}"
        )
    else:
        print("  GPS:          No disponible")
    if exif.get("error"):
        print(f"  Aviso:        {exif['error']}")
    print("-" * 60)
    print("INTEGRIDAD (HASHES)")
    print(f"  MD5:          {resultado['hashes']['MD5']}")
    print(f"  SHA256:       {resultado['hashes']['SHA256']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
