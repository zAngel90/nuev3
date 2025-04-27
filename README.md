# CYF Store Backend

Backend para la tienda de productos gaming CYF Store, implementado con Node.js y usando archivos JSON como base de datos.

## Configuración

1. Instalar dependencias:
```bash
npm install
```

2. Iniciar el servidor:
```bash
npm run dev
```

El servidor se iniciará en el puerto 5000.

## Credenciales de Admin

- Username: admin
- Password: admin123

## Endpoints

### Autenticación

- POST `/api/auth/register` - Registrar nuevo usuario
  ```json
  {
    "username": "string",
    "email": "string",
    "password": "string"
  }
  ```

- POST `/api/auth/login` - Iniciar sesión
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```

### Categorías

- GET `/api/categories` - Obtener todas las categorías
- POST `/api/categories` - Crear nueva categoría (requiere auth admin)
  ```json
  {
    "name": "string",
    "description": "string"
  }
  ```
- PUT `/api/categories/:id` - Actualizar categoría (requiere auth admin)
  ```json
  {
    "name": "string",
    "description": "string"
  }
  ```
- DELETE `/api/categories/:id` - Eliminar categoría (requiere auth admin)

### Productos

- GET `/api/products` - Obtener todos los productos
- POST `/api/products` - Crear nuevo producto (requiere auth admin)
  ```json
  {
    "name": "string",
    "description": "string",
    "price": number,
    "category": "string",
    "tag": "string",
    "image": File
  }
  ```

- PUT `/api/products/:id` - Actualizar producto (requiere auth admin)
- DELETE `/api/products/:id` - Eliminar producto (requiere auth admin)

## Estructura de Archivos

```
backend/
  ├── data/
  │   ├── users.json
  │   ├── products.json
  │   └── categories.json
  ├── uploads/
  │   └── products/
  ├── server.js
  ├── package.json
  └── README.md
```

## Notas

- Las imágenes se guardan en la carpeta `uploads/products`
- Solo los usuarios admin pueden crear/editar/eliminar productos y categorías
- Los tokens JWT expiran en 24 horas
- Las categorías incluyen un slug generado automáticamente para URLs amigables 