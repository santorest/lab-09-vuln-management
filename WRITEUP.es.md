---
title: "Flujo de gestión de vulnerabilidades (Greenbone, EPSS, KEV)"
id: "lab-09-vuln-management"
category: "Evaluación de vulnerabilidades y pentesting"
type: "Laboratorio"
status: "completado"
date: "2026-10-01"
time_to_reproduce: "Una ejecución de CI (fork, activar Actions, ejecutar CI); la duración medida está en los Resultados"
skills: [Greenbone, OpenVAS, Python, python-gvm, EPSS, CISA KEV, CVSS, Docker, Debian, GitHub Actions]
frameworks: [CIS Controls v8 (1.1, 7.1, 7.2, 7.5, 7.6, 7.7), MITRE ATT&CK (T1190, T1210, T1068)]
repo: "https://github.com/santorest/lab-09-vuln-management"
bundle: "Publicado en el sitio del portafolio con su checksum SHA-256"
---

# Flujo de gestión de vulnerabilidades (Greenbone, EPSS, KEV)

> **Resumen:** tres hosts de laboratorio desactualizados a propósito se escanean con Greenbone (por red y
> autenticado por SSH); cada hallazgo se prioriza con CVSS, EPSS, CISA KEV y la criticidad del activo según una
> política escrita, se registra con un responsable y una fecha límite de SLA, se corrige, se vuelve a escanear y se
> reporta. Una compuerta hace fallar la ejecución si queda un P1 o P2 abierto sin una excepción válida. Todo se
> ejecuta en GitHub Actions contra contenedores. **Las ejecuciones de CI son reales; los hosts son contenedores de
> laboratorio.** No se escanea ninguna red real.

| | |
|---|---|
| **Rol** | Ingeniero de seguridad que monta un proceso de gestión de vulnerabilidades para una flota pequeña |
| **Entorno** | Repositorio público de GitHub, runners Ubuntu de GitHub, contenedores de Greenbone Community Edition, tres contenedores Debian 12 |
| **Herramientas** | Greenbone CE (gvmd, ospd-openvas, openvasd), python-gvm, Python 3.12, API de EPSS de FIRST, catálogo KEV de CISA, pytest, ruff, mypy, gitleaks |
| **Entregable** | Herramienta de orquestación del escaneo, normalización, priorización, seguimiento, métricas y reporte; archivos de política; imágenes de la flota antes y después; CI con compuerta; ruleset de rama; PR de demostración |

---

## 1. Problema

Un escáner produce cientos de resultados; un equipo puede corregir unos pocos esta semana. La gestión de
vulnerabilidades es el proceso alrededor del escáner: saber qué se tiene, escanearlo con una frecuencia definida,
decidir qué va primero con una regla que cualquiera pueda volver a ejecutar, dar a cada hallazgo un responsable y una
fecha límite, probar la corrección con un nuevo escaneo y aceptar el resto del riesgo a conciencia, con un nombre y
una fecha de vencimiento. Este laboratorio construye ese proceso de principio a fin y lo mide.

## 2. Diseño

- **Ciclo.** Escanear la flota v1 → normalizar → enriquecer con EPSS y KEV → priorizar → seguimiento → corregir (flota
  v2) → volver a escanear → actualizar el seguimiento → métricas y reporte → compuerta. `scripts/run-cycle.sh` es el
  ciclo completo, en CI y en local.
- **Primero el inventario.** `policy/assets.csv` lista cada host con su dirección, el rol responsable, la criticidad
  (1–3) y la exposición. El escaneo apunta exactamente a esa lista.
- **La política como archivos.** `policy/policy.yaml` contiene la frecuencia, los días de SLA por prioridad, el piso de
  CVSS y los umbrales; `policy/exceptions.yaml` contiene las aceptaciones de riesgo. `docs/policy.md` dice lo mismo en
  prosa.
- **Sin pérdida silenciosa de cobertura.** Un escaneo que no termina, un tiempo de espera agotado o un host del
  inventario ausente del reporte es un error (código 2), nunca "0 hallazgos". Un nuevo escaneo que se saltara un host
  sin avisar parecería una corrección perfecta.
- **Greenbone en CI.** Los contenedores de la comunidad se ejecutan sin la interfaz web; el feed es un conjunto de
  imágenes de datos fijadas por digest, así que una ejecución no depende de una sincronización en vivo. La orquestación
  habla GMP por el socket Unix de gvmd con python-gvm: espera a que el escáner y la configuración "Full and fast" estén
  listos, crea una credencial SSH desechable y un objetivo, ejecuta una tarea y descarga el reporte XML.

## 3. Priorización

Gana la primera regla que se cumple (`docs/prioritization.md` tiene ejemplos resueltos):

| Regla | Prioridad |
|---|---|
| Algún CVE del hallazgo está en CISA KEV | P1 |
| EPSS ≥ 0,10 y CVSS ≥ 7,0 | P1 |
| CVSS ≥ 9,0, o CVSS ≥ 7,0 en un activo de criticidad 3 o expuesto a internet | P2 |
| CVSS ≥ 7,0, o EPSS ≥ 0,10 | P3 |
| CVSS ≥ 4,0 | P4 |
| por debajo de 4,0 | informativo |

KEV va primero porque registra una explotación que está ocurriendo; EPSS ordena lo probable; CVSS y el activo dicen
qué tan grave y dónde. Un hallazgo con varios CVE toma el peor valor de cada entrada; un CVE sin puntaje EPSS cuenta
como 0 y se muestra como "EPSS unknown"; un hallazgo de configuración sin CVE se ordena por CVSS y por el activo. Cada
fila guarda sus entradas y el texto de la regla que decidió.

## 4. Seguimiento y excepciones

Una fila por host y prueba de Greenbone: prioridad, CVSS, EPSS, KEV, regla, responsable, fecha de apertura, fecha
límite (fecha del escaneo más el SLA), estado y fecha de cierre. Tras el nuevo escaneo una fila queda `fixed` (ausente
en el nuevo escaneo del mismo host), `open` (sigue presente) o `new` (solo en el nuevo escaneo). Una excepción
necesita un motivo, el rol que la aprueba y una fecha de vencimiento: mientras es válida la fila queda `risk accepted`;
al vencer pasa a `reopened` y vuelve a contar para la compuerta. Salida: `tracker.csv` y `tracker.md`.

## 5. Flota y corrección

| Host | Rol | v1 ("como se encontró") | Criticidad / exposición | v2 (corregido) |
|---|---|---|---|---|
| `web` | servidor web | Debian 12.0, openssh-server y nginx del snapshot del 2023-06-15 | 3, expuesto a internet | paquetes y actualizaciones de seguridad actuales; `server_tokens off` |
| `files` | servidor de archivos | Debian 12.0, openssh-server y vsftpd, FTP anónimo activo | 2, interno | paquetes actuales; FTP anónimo desactivado |
| `db` | host de base de datos | Debian 12.0, openssh-server y postgresql-15 | 3, interno | paquetes actuales |

Las imágenes v1 están fijadas al archivo de snapshots de Debian a propósito, para que cada ejecución escanee el mismo
estado "como se encontró". La corrección es lo que haría un equipo: actualizar los paquetes y corregir la
configuración, reconstruir en las mismas direcciones y volver a escanear.

## 6. Pipeline

| Job | Qué prueba |
|---|---|
| `lint` | ruff y mypy (estricto) |
| `unit` | cada módulo puro contra fixtures (hallazgo sin CVE, varios CVE, EPSS ausente, KEV por encima de un puntaje bajo, excepción vencida, nuevo en el nuevo escaneo, host ausente) y la orquestación contra un GMP falso; umbral de cobertura del 90 % |
| `scan` | el ciclo completo contra Greenbone y la flota; artefactos: ambos reportes, los snapshots de EPSS/KEV, el seguimiento, las métricas y el reporte HTML; resumen Markdown del job |
| `secrets` | gitleaks sobre todo el historial |

Se ejecuta en cada pull request, en los push a `main`, cada semana (la frecuencia de la política) y a demanda. Un
ruleset en `main` exige pull request y los cuatro jobs.

## 7. Resultados

Los resultados se agregan a partir de las primeras ejecuciones de CI.

## 8. Lecciones

- **Greenbone carga sus datos en orden.** En un runner, gvmd pasó unos 38 minutos importando los feeds SCAP y CERT
  antes de empezar con las pruebas de vulnerabilidades, y las configuraciones de escaneo solo existen después de
  ellas. Los hallazgos no necesitan datos SCAP ni CERT (las referencias a CVE vienen con las pruebas; EPSS y KEV los
  aporta esta herramienta), así que el laboratorio no los carga.
- **Revisar la biblioteca, no la documentación que se recuerda.** El primer spike habría fallado al importar: la
  transformación de python-gvm se llama `EtreeCheckCommandTransform`. mypy lo encontró antes que CI.

## 9. Límites

- Contenedores, no hosts reales; no se escanea ninguna red real.
- El feed comunitario de Greenbone es un snapshot fijado; los feeds SCAP y CERT no se cargan.
- EPSS y KEV se consultan en la fecha de la ejecución, así que una ejecución posterior puede priorizar el mismo
  hallazgo de otra forma; cada ejecución guarda los snapshots que usó.
- El tiempo de corrección se mide en minutos dentro de una ejecución, no en días.
- No hay un sistema de tickets real: el seguimiento es un archivo CSV/Markdown.
- El escaneo autenticado de aplicaciones web está fuera del alcance.

## 10. Reproducirlo

Haga un fork del repositorio y active Actions: cada push ejecuta el ciclo completo. En local (Linux, macOS o WSL con
Docker), siga el inicio rápido del README: `bash scripts/run-cycle.sh` escribe los reportes, los snapshots, el
seguimiento y `out/report.html`.

## 11. Correspondencia

| Marco | Elementos |
|---|---|
| CIS Controls v8 | 1.1 inventario detallado de activos, 7.1 proceso de gestión de vulnerabilidades, 7.2 proceso de corrección, 7.5 escaneos automatizados de activos internos (autenticados), 7.6 escaneos automatizados de activos expuestos, 7.7 corregir las vulnerabilidades detectadas |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application, T1210 Exploitation of Remote Services, T1068 Exploitation for Privilege Escalation — las técnicas que habilitan los servicios y paquetes sin parchear de la flota v1 |
