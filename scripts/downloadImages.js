const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  {
    name: 'premium-pass.jpg',
    url: 'https://images.unsplash.com/photo-1614680376573-df3480f0c6ff'
  },
  {
    name: 'legendary-sword.jpg',
    url: 'https://images.unsplash.com/photo-1589187832032-3e560ed4e6b9'
  },
  {
    name: 'galaxy-skin.jpg',
    url: 'https://images.unsplash.com/photo-1534796636912-3b95b3ab5986'
  },
  {
    name: 'vip-membership.jpg',
    url: 'https://images.unsplash.com/photo-1614680376408-16359d2e1cf4'
  },
  {
    name: 'battle-pass.jpg',
    url: 'https://images.unsplash.com/photo-1538481199705-c710c4e965fc'
  },
  {
    name: 'mythic-pet.jpg',
    url: 'https://images.unsplash.com/photo-1577083288073-40892c0860a4'
  },
  {
    name: 'ninja-skin.jpg',
    url: 'https://images.unsplash.com/photo-1578353022142-09264fd64295'
  },
  {
    name: 'starter-pack.jpg',
    url: 'https://images.unsplash.com/photo-1614680376739-414d95ff43df'
  }
];

const downloadImage = (url, filename) => {
  return new Promise((resolve, reject) => {
    const dir = path.join(__dirname, '..', 'uploads', 'products');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const filepath = path.join(dir, filename);
    const file = fs.createWriteStream(filepath);

    https.get(`${url}?w=500&q=80`, (response) => {
      response.pipe(file);
      file.on('finish', () => {
        file.close();
        console.log(`Downloaded: ${filename}`);
        resolve();
      });
    }).on('error', (err) => {
      fs.unlink(filepath, () => {});
      reject(err);
    });
  });
};

async function downloadAll() {
  try {
    console.log('Starting downloads...');
    await Promise.all(images.map(img => downloadImage(img.url, img.name)));
    console.log('All images downloaded successfully!');
  } catch (error) {
    console.error('Error downloading images:', error);
  }
}

downloadAll(); 