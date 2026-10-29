const http = require("http");
const crypto = require("crypto");

const PUERTO = 3000;

// Almacena los usuarios registrados mientras el servidor está encendido.
const usuarios = new Map();

// Convierte la contraseña en un hash para no guardarla como texto.
function protegerContrasena(contrasena, sal) {
    return crypto.scryptSync(contrasena, sal, 64);
}

// Envía una respuesta en formato JSON.
function responder(res, codigo, datos) {
    res.writeHead(codigo, {
        "Content-Type": "application/json; charset=utf-8"
    });
    res.end(JSON.stringify(datos));
}

// Recibe los datos enviados al servicio web.
const servidor = http.createServer((req, res) => {
    if (req.method !== "POST" ||
        !["/registro", "/login"].includes(req.url)) {
        return responder(res, 404, {
            error: "Ruta no encontrada"
        });
    }

    let cuerpo = "";

    req.on("data", fragmento => {
        cuerpo += fragmento;

        // Limita el tamaño de los datos recibidos.
        if (cuerpo.length > 10000) {
            req.destroy();
        }
    });

    req.on("end", () => {
        let datos;

        try {
            datos = JSON.parse(cuerpo);
        } catch {
            return responder(res, 400, {
                error: "Los datos deben estar en formato JSON"
            });
        }

        const { usuario, contrasena } = datos || {};

        // Comprueba que los campos estén completos.
        if (typeof usuario !== "string" ||
            typeof contrasena !== "string" ||
            !usuario.trim() || !contrasena) {
            return responder(res, 400, {
                error: "Debes ingresar usuario y contraseña"
            });
        }

        if (req.url === "/registro") {
            // Evita registrar dos veces el mismo usuario.
            if (usuarios.has(usuario)) {
                return responder(res, 409, {
                    error: "El usuario ya está registrado"
                });
            }

            const sal = crypto.randomBytes(16).toString("hex");
            const hash = protegerContrasena(contrasena, sal);

            usuarios.set(usuario, { sal, hash });

            return responder(res, 201, {
                mensaje: "Usuario registrado satisfactoriamente"
            });
        }

        // Comprueba las credenciales durante el inicio de sesión.
        const registrado = usuarios.get(usuario);

        if (!registrado) {
            return responder(res, 401, {
                error: "Error en la autenticación"
            });
        }

        const hashIngresado = protegerContrasena(
            contrasena,
            registrado.sal
        );

        if (!crypto.timingSafeEqual(
            hashIngresado,
            registrado.hash
        )) {
            return responder(res, 401, {
                error: "Error en la autenticación"
            });
        }

        return responder(res, 200, {
            mensaje: "Autenticación satisfactoria"
        });
    });
});

// Inicia el servicio web.
servidor.listen(PUERTO, () => {
    console.log(`Servidor iniciado en http://localhost:${PUERTO}`);
});