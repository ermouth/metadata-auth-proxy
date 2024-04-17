/**
 * Кеширует в mdm справочники жалюзи
 * @module foroom
 *
 * Created by Evgeniy Malyarov on 19.03.2020.
 */

const fs = require('fs');
const path = require('path');
const unzip = require('unzipper');

const dir = path.resolve(__dirname, './foroom');

function prm_move(arr, alias) {
  const prm = arr.find((v) => v.alias === alias);
  if(prm) {
    arr.splice(arr.indexOf(prm), 1);
    arr.unshift(prm);
  }
}

function refresh(log) {
  // тянем файлы данных
  return fetch('https://api.foroom.ru/uploads/download/zip/data_new.zip')
    .then((res) => {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(reject, 30000);
        res.body.pipe(unzip.Extract({path: dir})).on('finish', () => {
          clearTimeout(timer);
          setTimeout(resolve, 10000);
        });
      })
    })
    .then(async () => {
      const files = fs.readdirSync(dir);
      const data = {};
      for (let i = 0; i < files.length; i++) {
        if(files[i].startsWith('.') || !files[i].endsWith('.json')) {
          continue;
        }
        const filename = path.join(dir, files[i]);
        try {
          const mtext = await fs.readFileAsync(filename, 'utf8');
          data[files[i].replace(/(get_|\.json)/g, '')] = JSON.parse(mtext).data;
        }
        catch(err) {
          err = null;
        }
      }
      if(data.all_data && data.all_data.izd) {
        data.all_data.izd = data.all_data.izd
          .filter((v) => v && v.enabled === 'all')
          .map((v) => {
            // сортируем параметры
            if(Array.isArray(v.params)) {
              ['gab_height', 'gab_width', 'height', 'width', 'amount'].forEach((alias) => prm_move(v.params, alias));
            }
            return v;
          });
      }
      return fs.writeFileAsync(path.join(dir, 'index.json'), JSON.stringify(data), 'utf8');
    })
    .then(() => fetch('https://api.foroom.ru/uploads/download/js/foroomApi.min.js'))
    .then((res) => {
      res.body.pipe(fs.createWriteStream(path.join(dir, 'api.js')));
    })
    .catch(() => {
      return null;
    })
    .then(() => setTimeout(refresh.bind(null, log), 36e5));
}

module.exports = function foroom($p, log) {
  refresh(log);
};
