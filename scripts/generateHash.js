const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

async function generateHash() {
  try {
    // Generar el hash de la contraseña
    const password = 'admin123';
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Leer el archivo users.json
    const usersPath = path.join(__dirname, '..', 'data', 'users.json');
    const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));

    // Actualizar la contraseña del admin
    usersData.users[0].password = hashedPassword;

    // Guardar el archivo actualizado
    fs.writeFileSync(usersPath, JSON.stringify(usersData, null, 2));

    console.log('Hash generado y archivo actualizado correctamente');
    console.log('Nueva contraseña hasheada:', hashedPassword);
    console.log('\nCredenciales de acceso:');
    console.log('Usuario: admin');
    console.log('Contraseña: admin123');
  } catch (error) {
    console.error('Error:', error);
  }
}

generateHash(); 