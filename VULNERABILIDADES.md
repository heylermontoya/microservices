# Análisis y remediación de vulnerabilidades — Backend .NET

**Proyecto:** `CatalogMicroservice` (repositorio `aelassas/microservices`)
**Framework:** ASP.NET Core, `net8.0`
**Herramientas:** Trivy 0.74.0 (`fs`, modo SCA) + `dotnet list package --vulnerable`
**Resultado:** de **6 hallazgos a 0**, en todas las severidades.

---

## Índice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Cómo se hizo el escaneo (y una trampa importante)](#2-cómo-se-hizo-el-escaneo-y-una-trampa-importante)
3. [Conceptos previos: directa vs. transitiva](#3-conceptos-previos-directa-vs-transitiva)
4. [Los 6 hallazgos, uno por uno](#4-los-6-hallazgos-uno-por-uno)
5. [Estrategia de remediación: el criterio](#5-estrategia-de-remediación-el-criterio)
6. [Qué se cambió exactamente](#6-qué-se-cambió-exactamente)
7. [Problemas que aparecieron y cómo se resolvieron](#7-problemas-que-aparecieron-y-cómo-se-resolvieron)
8. [Verificación final](#8-verificación-final)
9. [Cómo reproducirlo](#9-cómo-reproducirlo)

---

## 1. Resumen ejecutivo

| | Antes | Después |
|---|---|---|
| CRITICAL | 0 | **0** |
| HIGH | **4** | **0** |
| MEDIUM | **2** | **0** |
| LOW | 0 | **0** |
| **Total** | **6** | **0** |

Las 6 vulnerabilidades eran **transitivas**: ninguna estaba en un paquete que el proyecto
declarara directamente. Venían arrastradas por `MongoDB.Driver`, por los paquetes de
*health checks* y por el propio framework de .NET 8.

Todo se cerró con **2 actualizaciones de paquete padre** y **3 elevaciones puntuales**, sin
cambiar el *target framework* y sin reescribir lógica de negocio.

**Estado del proyecto tras los cambios:**

- `dotnet build store.sln` → 0 errores, 0 advertencias
- `dotnet test store.sln` → 14/14 tests pasando
- API probada en runtime contra MongoDB real (GET y POST con JWT)

---

## 2. Cómo se hizo el escaneo (y una trampa importante)

El comando que pide el reto es:

```powershell
trivy fs --scanners vuln --severity CRITICAL,HIGH <ruta>
```

Pero ejecutado tal cual sobre este proyecto, Trivy reportaba **una sola vulnerabilidad**.
El escaneo real tiene 4 HIGH. ¿Por qué la diferencia?

### El problema

Trivy necesita un archivo que describa el árbol de dependencias. En un proyecto .NET tiene
dos candidatos:

| Archivo | Qué contiene | Sirve para SCA |
|---|---|---|
| `bin/Debug/net8.0/*.deps.json` | Solo los assets que se **copian** al compilar | ❌ Incompleto |
| `packages.lock.json` | El **grafo completo**: directas + transitivas resueltas | ✅ Correcto |

El proyecto no traía `packages.lock.json`, así que Trivy caía en el `deps.json` de `bin/`.
Ese archivo **no lista los paquetes que forman parte del *shared framework*** de .NET
(como `System.Text.Json` o `Microsoft.Extensions.Caching.Memory`), porque esos no se copian
a la carpeta de salida — vienen con el runtime instalado. Resultado: 3 de las 4 HIGH quedaban
invisibles.

### La solución

Generar el lock file, que además es lo correcto para CI (builds reproducibles):

```powershell
dotnet restore src\microservices\CatalogMicroservice\CatalogMicroservice.csproj --use-lock-file
```

Y excluir `bin/` y `obj/` del escaneo, para que Trivy no cuente dos veces el mismo hallazgo:

```powershell
cd src\microservices\CatalogMicroservice
trivy fs --scanners vuln --severity CRITICAL,HIGH --skip-dirs bin --skip-dirs obj .
```

### La validación cruzada

Con el lock file, Trivy encontró **4 HIGH**. El escáner nativo de Microsoft encontró
exactamente los mismos paquetes:

```powershell
dotnet list package --vulnerable --include-transitive
```

Que **dos herramientas independientes** (Trivy con la base GHSA/NVD, NuGet con la suya) den el
mismo resultado es lo que confirma que el escaneo es correcto. Un solo output no basta.

> **Cómo saber que estás escaneando bien:** en la tabla de Trivy, la columna `Target` debe
> decir `packages.lock.json` y el `Type` debe ser `nuget`. Si dice `deps.json` / `dotnet-core`,
> estás viendo un escaneo incompleto.

---

## 3. Conceptos previos: directa vs. transitiva

Para entender las decisiones que vienen, hace falta esta distinción:

- **Dependencia directa** — la declaras tú en el `.csproj`. Ejemplo: `MongoDB.Driver`.
- **Dependencia transitiva** — no la pediste; llega porque un paquete tuyo la necesita.
  Ejemplo: `Snappier` llega porque `MongoDB.Driver` lo usa para compresión.

Esto importa porque **no puedes actualizar una transitiva editándola directamente** — no está
en tu `.csproj`. Tienes dos caminos:

1. **Actualizar el padre.** Subes `MongoDB.Driver` y él trae una versión nueva de `Snappier`.
   *Ventaja:* arreglas la causa. *Riesgo:* el padre puede traer cambios que rompan.
2. **Pinear (elevar) la transitiva.** Declaras `Snappier` como referencia directa con la versión
   parcheada. En NuGet, **una referencia directa gana sobre la resolución transitiva**.
   *Ventaja:* cambio quirúrgico. *Riesgo:* el padre sigue viejo, y volverás a tener el problema
   con el siguiente CVE.

La regla aplicada aquí: **actualizar el padre siempre que se pueda; pinear solo cuando no exista
un padre actualizable.**

---

## 4. Los 6 hallazgos, uno por uno

### 🔴 HIGH — CVE-2024-30105 · `System.Text.Json` 8.0.0

| | |
|---|---|
| **Tipo** | Denegación de servicio (DoS) |
| **Origen** | Transitiva — shared framework de .NET 8 |
| **Versión parcheada** | 8.0.4 |

**Qué es.** Un fallo en la deserialización asíncrona de JSON. Una carga maliciosa puede provocar
consumo desmedido de recursos y tumbar el proceso.

**Por qué importa AQUÍ — riesgo REAL y ALTO.** El controlador expone:

```csharp
[HttpPost]
[Authorize]
public IActionResult Post([FromBody] CatalogItem catalogItem)
```

Ese `[FromBody]` significa que **el cuerpo JSON lo controla quien llama a la API**, y ASP.NET Core
lo deserializa con `System.Text.Json`. Es exactamente el camino que el CVE describe. Lo mismo en
el `PUT`. No es teórico: es la ruta de código principal del microservicio.

---

### 🔴 HIGH — CVE-2024-43485 · `System.Text.Json` 8.0.0

| | |
|---|---|
| **Tipo** | Denegación de servicio (DoS) |
| **Origen** | Transitiva — shared framework de .NET 8 |
| **Versión parcheada** | 8.0.5 |

**Qué es.** Segundo vector de DoS en el mismo paquete, esta vez explotando el manejo de ciertos
tipos durante la deserialización.

**Por qué importa AQUÍ.** Misma superficie que el anterior: los endpoints `POST` y `PUT`.
Al ser el mismo paquete, una sola actualización cierra ambos CVEs.

---

### 🔴 HIGH — CVE-2024-43483 · `Microsoft.Extensions.Caching.Memory` 8.0.0

| | |
|---|---|
| **Tipo** | *Hash flooding* → DoS |
| **Origen** | Transitiva — vía `AspNetCore.HealthChecks.UI` |
| **Versión parcheada** | 8.0.1 |

**Qué es.** Un atacante que controle las claves de un diccionario puede fabricarlas para que
todas colisionen en el mismo *bucket*. La estructura degenera de O(1) a O(n) y el CPU se dispara.

**Por qué importa AQUÍ — riesgo BAJO, pero se corrige igual.** En este proyecto el paquete solo
lo usa el almacenamiento en memoria del *Health Checks UI*:

```csharp
services.AddHealthChecksUI().AddInMemoryStorage();
```

Las claves de esa caché las genera el propio framework a partir de la configuración, **no de
entrada del usuario**. Sin control sobre las claves, no hay *hash flooding*.

**Decisión: se remedia igualmente.** El coste es una línea en el `.csproj` y cero riesgo de
regresión. No se justifica dejar una HIGH abierta por comodidad, y el análisis de superficie no
es garantía permanente — mañana alguien podría exponer esa caché a datos externos.

---

### 🔴 HIGH — CVE-2026-44302 · `Snappier` 1.0.0

| | |
|---|---|
| **Tipo** | Bucle infinito → DoS |
| **Origen** | Transitiva — vía `MongoDB.Driver` 2.24.0 |
| **Versión parcheada** | 1.3.1 |

**Qué es.** `Snappier` implementa el algoritmo de compresión Snappy. Al descomprimir un *stream*
"framed" malformado, entra en un bucle infinito: el hilo se queda girando al 100 % de CPU.

**Por qué importa AQUÍ — riesgo BAJO.** El driver solo usa Snappy si la compresión está
**negociada explícitamente** con el servidor MongoDB. La cadena de conexión de este proyecto es:

```
mongodb://127.0.0.1:27017
```

Sin `compressors=snappy`, ese código nunca se ejecuta. Además, para explotarlo haría falta un
servidor Mongo malicioso o un atacante en medio de la conexión.

**Decisión: se remedia.** Aunque el camino esté inactivo hoy, **la librería vulnerable viaja
dentro del artefacto desplegado**. Cualquier escáner (y cualquier auditoría) la va a marcar, y
basta que alguien añada compresión a la cadena de conexión para activarla.

---

### 🟠 MEDIUM — GHSA-6c8g-7p36-r338 · `SharpCompress` 0.30.1

| | |
|---|---|
| **Tipo** | Path traversal al extraer archivos |
| **Origen** | Transitiva — vía `MongoDB.Driver` 2.24.0 |
| **Versión parcheada** | 0.48.1 (resuelta al subir el driver) |

**Qué es.** Al extraer un archivo comprimido, no se validan correctamente las rutas internas.
Una entrada con `../../` puede escribir fuera del directorio de destino.

**Por qué importa AQUÍ — riesgo MUY BAJO.** El microservicio no extrae archivos comprimidos en
ningún punto. `SharpCompress` llega como dependencia de compresión del driver de Mongo y su
código nunca se invoca.

**Decisión: se remedia sin coste adicional**, porque venía en el mismo paquete de la actualización
de `MongoDB.Driver`.

---

### 🟠 MEDIUM — CVE-2025-9708 (GHSA-w7r3-mgwf-4mqq) · `KubernetesClient` 12.1.1

| | |
|---|---|
| **Tipo** | Validación incorrecta de certificados TLS |
| **Origen** | Transitiva — vía `AspNetCore.HealthChecks.UI` |
| **Versión parcheada** | 17.0.14 |

**Qué es.** El cliente de Kubernetes acepta certificados de **cualquier CA** sin verificar
correctamente la cadena de confianza. Abre la puerta a un ataque *man-in-the-middle* contra la
comunicación con el API server de Kubernetes.

**Por qué importa AQUÍ — riesgo MUY BAJO.** El paquete llega porque *Health Checks UI* soporta
descubrimiento automático de servicios en Kubernetes. Este proyecto **no corre en Kubernetes** y
no usa esa función.

**Decisión: se remedia.** Esta fue la más laboriosa —ver la sección 7— porque incluso la versión
más reciente del paquete padre sigue arrastrando una versión vulnerable.

---

## 5. Estrategia de remediación: el criterio

Antes de tocar nada, se consultaron los `.nuspec` publicados en NuGet para ver **qué dependencias
trae cada versión candidata**:

```bash
curl -s "https://api.nuget.org/v3-flatcontainer/mongodb.driver/3.11.1/mongodb.driver.nuspec"
```

Eso reveló que un solo *upgrade* podía cerrar varios hallazgos a la vez:

| Actualización del padre | Lo que arrastra | Hallazgos que cierra |
|---|---|---|
| `MongoDB.Driver` 2.24.0 → **3.11.1** | `Snappier` 1.0.0 → **1.3.1**<br>`SharpCompress` 0.30.1 → **0.48.1** | 1 HIGH + 1 MEDIUM |
| `AspNetCore.HealthChecks.*` 8.0.0 → **9.0.0** | `KubernetesClient` 12.1.1 → **15.0.1** | (parcial, ver §7) |

Y dónde **no existía** padre actualizable, se recurrió al *pin*:

| Elevación directa | Motivo por el que no hay alternativa |
|---|---|
| `System.Text.Json` → **8.0.6** | Viene del shared framework de `net8.0`. El único "padre" es el propio runtime; subirlo exigiría cambiar de *target framework* |
| `Microsoft.Extensions.Caching.Memory` → **8.0.1** | Ídem |
| `KubernetesClient` → **17.0.14** | `HealthChecks.UI` 9.0.0 —la última publicada— sigue resolviendo la 15.0.1, todavía vulnerable |

### Lo que deliberadamente NO se tocó

| Paquete | Versión | Por qué se deja |
|---|---|---|
| `Swashbuckle.AspNetCore` | 6.5.0 | **Cero hallazgos.** Subirlo añade riesgo de regresión en la generación de Swagger sin ninguna ganancia de seguridad |
| `Serilog.AspNetCore` | 8.0.1 | **Cero hallazgos.** Mismo razonamiento |
| `Microsoft.VisualStudio.Azure.Containers.Tools.Targets` | 1.19.6 | **Cero hallazgos.** Es solo tooling de build para Docker |

> Actualizar paquetes que no tienen vulnerabilidades no es "más seguro": es introducir cambios sin
> justificación y ampliar la superficie de regresión. Cada cambio en un `.csproj` debe poder
> defenderse con un CVE concreto.

---

## 6. Qué se cambió exactamente

### `CatalogMicroservice.csproj`

```xml
<ItemGroup>
  <!-- Actualizados: cada uno resuelve transitivas vulnerables -->
  <PackageReference Include="AspNetCore.HealthChecks.MongoDb" Version="9.0.0" />
  <PackageReference Include="AspNetCore.HealthChecks.UI" Version="9.0.0" />
  <PackageReference Include="AspNetCore.HealthChecks.UI.Client" Version="9.0.0" />
  <PackageReference Include="AspNetCore.HealthChecks.UI.InMemory.Storage" Version="9.0.0" />
  <PackageReference Include="MongoDB.Driver" Version="3.11.1" />

  <!-- Sin cambios: no presentan hallazgos -->
  <PackageReference Include="Microsoft.VisualStudio.Azure.Containers.Tools.Targets" Version="1.19.6" />
  <PackageReference Include="Serilog.AspNetCore" Version="8.0.1" />
  <PackageReference Include="Swashbuckle.AspNetCore" Version="6.5.0" />
</ItemGroup>

<!--
  Remediación: referencias directas que elevan transitivas.
  Una PackageReference directa gana sobre la resolución transitiva de NuGet.
-->
<ItemGroup>
  <PackageReference Include="System.Text.Json" Version="8.0.6" />
  <PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="8.0.1" />
  <PackageReference Include="KubernetesClient" Version="17.0.14" />
</ItemGroup>
```

### `Middleware.csproj`

```xml
<PackageReference Include="MongoDB.Driver" Version="3.11.1" />   <!-- era 2.24.0 -->
```

### Cambio de código en `Startup.cs`

La versión 9.0.0 de `AspNetCore.HealthChecks.MongoDb` **eliminó** la sobrecarga que recibía un
*connection string*. Antes:

```csharp
services.AddHealthChecks()
    .AddMongoDb(
        mongodbConnectionString: (
            Configuration.GetSection("mongo").Get<MongoOptions>()
            ?? throw new Exception("mongo configuration section not found")
        ).ConnectionString,
        name: "mongo",
        failureStatus: HealthStatus.Unhealthy
    );
```

Después:

```csharp
services.AddHealthChecks()
    .AddMongoDb(
        sp => sp.GetService<IMongoDatabase>()
              ?? throw new Exception("IMongoDatabase not found"),
        name: "mongo",
        failureStatus: HealthStatus.Unhealthy
    );
```

**El cambio mejora el diseño.** La versión anterior volvía a leer la configuración y creaba una
conexión aparte solo para el health check. La nueva **reutiliza el `IMongoDatabase` ya registrado
en el contenedor de inyección de dependencias**, así que el health check comprueba exactamente la
misma conexión que usa la aplicación. Eso es lo que un health check debería hacer.

### Alcance total del cambio

**11 archivos modificados:**

```
src/microservices/CatalogMicroservice/CatalogMicroservice.csproj
src/microservices/CatalogMicroservice/Startup.cs
src/microservices/CartMicroservice/CartMicroservice.csproj
src/microservices/CartMicroservice/Startup.cs
src/microservices/IdentityMicroservice/IdentityMicroservice.csproj
src/microservices/IdentityMicroservice/Startup.cs
src/gateways/BackendGateway/BackendGateway.csproj
src/gateways/BackendGateway/Startup.cs
src/gateways/FrontendGateway/FrontendGateway.csproj
src/gateways/FrontendGateway/Startup.cs
src/middlewares/Middleware/Middleware.csproj
```

Por qué se tocaron proyectos fuera del alcance del reto → siguiente sección.

---

## 7. Problemas que aparecieron y cómo se resolvieron

### Problema 1 — La API del health check desapareció

```
error CS1739: La mejor sobrecarga para 'AddMongoDb' no tiene un parámetro
denominado 'mongodbConnectionString'
```

**Diagnóstico.** En vez de adivinar la firma nueva, se inspeccionó la documentación XML que viene
dentro del propio paquete descargado:

```bash
grep -oE 'M:.*AddMongoDb\([^"]*\)' \
  ~/.nuget/packages/aspnetcore.healthchecks.mongodb/9.0.0/lib/net8.0/HealthChecks.MongoDb.xml
```

Eso reveló las dos sobrecargas disponibles: una que recibe `Func<IServiceProvider, IMongoClient>`
y otra `Func<IServiceProvider, IMongoDatabase>`.

**Solución.** Se usó la de `IMongoDatabase` (ver §6). En los **gateways** el caso era distinto:
no registran `IMongoDatabase` porque no acceden a datos —solo enrutan con Ocelot— y su
configuración de `mongo` ni siquiera trae el campo `database`. Ahí se construye el cliente y se
hace *ping* contra la base `admin`, que es la práctica estándar para una comprobación de
conectividad:

```csharp
.AddMongoDb(
    sp => new MongoClient(
        (Configuration.GetSection("mongo").Get<MongoOptions>()
         ?? throw new Exception("mongo configuration section not found")
        ).ConnectionString
    ).GetDatabase("admin"),
    name: "mongo",
    failureStatus: HealthStatus.Unhealthy
);
```

### Problema 2 — Efecto dominó por un proyecto compartido

Al subir `MongoDB.Driver` en `Middleware`, la solución entera dejó de compilar:

```
error NU1605: Degradación del paquete detectada: MongoDB.Driver de 3.11.1 a 2.24.0
  CartMicroservice -> Middleware -> MongoDB.Driver (>= 3.11.1)
  CartMicroservice -> MongoDB.Driver (>= 2.24.0)
```

**Qué pasó.** `Middleware` es un proyecto **compartido** por Catalog, Cart e Identity. Al subirle
el driver a 3.11.1, los otros microservicios —que seguían en 2.24.0— generaban un conflicto:
NuGet detecta que se le pide *degradar* un paquete y lo trata como error.

**Decisión.** El reto solo exige `CatalogMicroservice`, pero uno de los criterios de aceptación
es *"los proyectos compilan y corren sin errores"*. **Dejar la solución rota para cumplir el
alcance literal habría sido peor que ampliarlo.** Se propagó la actualización a los 4 proyectos
restantes.

**Lección general:** en una solución con proyectos compartidos, actualizar una dependencia nunca
es una operación local. Hay que mapear quién más la consume **antes** de tocarla.

### Problema 3 — El pin transitivo hay que repetirlo en cada proyecto

Tras el primer ciclo, el escaneo de `CatalogMicroservice` daba 0. Pero al escanear **el repositorio
completo**, seguía apareciendo `KubernetesClient` 15.0.1 en 8 targets distintos:

```
src/gateways/BackendGateway/bin/Debug/net8.0/BackendGateway.deps.json      → MEDIUM: 1
src/gateways/FrontendGateway/bin/Debug/net8.0/FrontendGateway.deps.json    → MEDIUM: 1
src/microservices/CartMicroservice/bin/Debug/net8.0/CartMicroservice...    → MEDIUM: 1
src/microservices/IdentityMicroservice/bin/Debug/net8.0/Identity...        → MEDIUM: 1
...
```

**Qué pasó.** Dos cosas se juntaron:

1. `AspNetCore.HealthChecks.UI` 9.0.0 —**la versión más reciente que existe**— sigue resolviendo
   `KubernetesClient` **15.0.1**, que ya está parcheada solo desde la **17.0.14**. Es decir:
   actualizar el padre al máximo disponible **no era suficiente**. Aquí el *pin* dejó de ser un
   atajo y pasó a ser la única opción.
2. El *pin* se había puesto **solo en `CatalogMicroservice`**. NuGet resuelve el grafo de
   dependencias **de forma independiente en cada proyecto**, así que una referencia directa en un
   `.csproj` no afecta a los demás.

**Solución.** Añadir la elevación en los 5 proyectos que usan `HealthChecks.UI`:

| Proyecto | Antes | Después |
|---|---|---|
| CatalogMicroservice | 17.0.14 ✅ | 17.0.14 |
| CartMicroservice | 15.0.1 ❌ | **17.0.14** |
| IdentityMicroservice | 15.0.1 ❌ | **17.0.14** |
| BackendGateway | 15.0.1 ❌ | **17.0.14** |
| FrontendGateway | 15.0.1 ❌ | **17.0.14** |

### Problema 4 — Resultados fantasma por artefactos viejos

Trivy seguía reportando versiones antiguas incluso después de corregir los `.csproj`. La causa:
los `deps.json` dentro de `bin/` eran de compilaciones anteriores.

**Solución — limpieza completa antes de reescanear:**

```powershell
Get-ChildItem -Recurse -Directory -Include bin,obj | Remove-Item -Recurse -Force
dotnet restore store.sln --force-evaluate
dotnet build store.sln
```

`--force-evaluate` es **obligatorio** cuando existe `packages.lock.json`: sin esa bandera,
`restore` respeta el lock file antiguo e **ignora los cambios del `.csproj`**.

---

## 8. Verificación final

Todo lo siguiente se ejecutó y se comprobó:

| Comprobación | Comando | Resultado |
|---|---|---|
| Compilación | `dotnet build store.sln` | ✅ 0 errores, 0 advertencias |
| Tests unitarios | `dotnet test store.sln` | ✅ **14/14** (Catalog 5, Cart 6, Identity 3) |
| Escáner nativo .NET | `dotnet list package --vulnerable --include-transitive` | ✅ *"no tiene paquetes vulnerables"* |
| Trivy, criterio del reto | `trivy fs --scanners vuln --severity CRITICAL,HIGH` | ✅ **0** |
| Trivy, todas las severidades | `trivy fs --scanners vuln` | ✅ **0** |
| Trivy, repositorio completo | `trivy fs --scanners vuln .` | ✅ **0** en los 18 targets |

### Verificación funcional en runtime

Compilar no es suficiente: `MongoDB.Driver` subió un *major* completo. Se probó el flujo real
contra una instancia de MongoDB:

| Prueba | Resultado |
|---|---|
| `GET /healthz` | ✅ `{"status":"Healthy"}`, Mongo responde en 69 ms |
| `GET /api/catalog` sin token | ✅ HTTP 401 (la autenticación sigue activa) |
| `POST /api/identity/login` | ✅ devuelve JWT válido |
| `GET /api/catalog` con Bearer | ✅ devuelve los documentos de la colección |
| `POST /api/catalog` con Bearer | ✅ crea documento, id `6a921398ed52405cec12d133` |

### Evidencia archivada

Los informes están versionados en este repositorio, en la carpeta `reports/`:

- **Pre-análisis** (línea base, antes de tocar nada): `reports/pre/`
- **Post-análisis** (estado remediado): `reports/post/`

```
reports/
├── pre/
│   ├── catalog.json                      escaneo Trivy inicial (JSON)
│   ├── catalog.txt                       escaneo Trivy inicial (tabla)
│   └── dotnet-list-vulnerable.txt        salida del escáner de NuGet
└── post/
    ├── catalog.json                      escaneo final (JSON)
    ├── catalog.txt                       escaneo final (tabla)
    ├── catalog-all-severities.txt        final sin filtro de severidad
    ├── solucion-completa.txt             repositorio entero, 18 targets
    └── dotnet-list-vulnerable.txt        confirmación cruzada de NuGet
```

---

## 9. Cómo reproducirlo

### Requisitos

- .NET SDK 8.0 o superior
- Trivy (`winget install -e --id AquaSecurity.Trivy`)
- MongoDB en `localhost:27017` — solo para las pruebas funcionales, no para el escaneo

### Escaneo del proyecto objetivo

```powershell
cd "<repo>\microservices\src\microservices\CatalogMicroservice"
trivy fs --scanners vuln --severity CRITICAL,HIGH --skip-dirs bin --skip-dirs obj .
```

Salida esperada: `Vulnerabilities: 0`, con `Target = packages.lock.json` y `Type = nuget`.

### Escaneo sin filtro (todas las severidades)

```powershell
trivy fs --scanners vuln --skip-dirs bin --skip-dirs obj .
```

### Escaneo del repositorio completo

```powershell
cd "<repo>\microservices"
trivy fs --scanners vuln .
```

### Validación cruzada con el escáner de Microsoft

```powershell
dotnet list package --vulnerable --include-transitive
```

### Gate para CI (falla el build si aparece algo)

```powershell
trivy fs --scanners vuln --severity CRITICAL,HIGH --exit-code 1 --skip-dirs bin --skip-dirs obj .
echo "Exit code: $LASTEXITCODE"
```

Debe imprimir `Exit code: 0`.

### Si regeneras el lock file desde cero

```powershell
cd "<repo>\microservices"
dotnet restore src\microservices\CatalogMicroservice\CatalogMicroservice.csproj --use-lock-file
```

Y si ya existía y cambiaste el `.csproj`:

```powershell
dotnet restore store.sln --force-evaluate
```

---

## Apéndice — Tabla resumen de hallazgos

| # | Severidad | CVE / GHSA | Paquete | De | A | Tipo de fallo | Riesgo real aquí | Técnica |
|---|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2024-30105 | `System.Text.Json` | 8.0.0 | 8.0.6 | DoS en deserialización | **Alto** — `[FromBody]` en POST/PUT | Pin |
| 2 | HIGH | CVE-2024-43485 | `System.Text.Json` | 8.0.0 | 8.0.6 | DoS en deserialización | **Alto** — misma superficie | Pin |
| 3 | HIGH | CVE-2024-43483 | `Microsoft.Extensions.Caching.Memory` | 8.0.0 | 8.0.1 | Hash flooding | Bajo — claves no controladas por el usuario | Pin |
| 4 | HIGH | CVE-2026-44302 | `Snappier` | 1.0.0 | 1.3.1 | Bucle infinito | Bajo — compresión no negociada | Upgrade del padre |
| 5 | MEDIUM | GHSA-6c8g-7p36-r338 | `SharpCompress` | 0.30.1 | 0.48.1 | Path traversal | Muy bajo — no se extraen archivos | Upgrade del padre |
| 6 | MEDIUM | CVE-2025-9708 | `KubernetesClient` | 12.1.1 | 17.0.14 | Validación de CA en TLS | Muy bajo — no corre en Kubernetes | Pin (×5 proyectos) |

**Ninguna vulnerabilidad quedó sin remediar.** No hay MEDIUM pendientes que justificar.
