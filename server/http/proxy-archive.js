/**
 * handler запросов к архивным базам
 *
 * 2024-09-18
 */

const {end401, end403, end500} = require('./end');

const https = require('https'),
      http = require('http'),
      httpProxy = require('http-proxy').createProxyServer;
const proxy = {
  http:  httpProxy({xfwd: true}),
  https: httpProxy({xfwd: true, agent: https.globalAgent, secure: false}),
};

module.exports = function ($p, log) {

  const {cat:{abonents}} = $p,
        auth = require('../auth')($p, log),
        conf = require('../../config/app.settings')();

  return async function proxy_by_year(req, res) {
    const {year, zone} = req.headers;
    if (!zone || !year) return;

    const key = parseFloat(year),
          abonent = abonents.by_id(zone);
    if(key == conf.server.year || abonent.is_new()) return;

    const yrow = abonent.servers.find({key});
    if(!yrow || !yrow.proxy) return;

    // TODO:
    // — возможно перехватывать и пересобирать /common с локальными формулами?

    const method = req.method.toLowerCase(),
          paths = req.parsed.paths.filter((e,i) => i||e!='couchdb'),
          path = paths.join('/'),
          combo = method + ' ' + path;

    // логи пишем локально
    if (/^post .+\d_log\/_/.test(combo)) {
      delete req.headers.year;
      return false;
    }

    // put, delete не разрешены
    if (!/^(get|post|options|head)$/.test(method)) {
      end403({req, res, err: 'Метод не разрешен для архива', log});
      return true;
    }

    // разрешаем по путям
    let isAllowed = [
      /^get /,
      /^post auth\/couchdb/,
      /^post [a-z]+_\d+_(doc|ram)\/_(all_docs|find)/,
      /^post [a-z]+_\d+_doc\/doc\.calc_order/,
    ].reduce((a, re) => a || re.test(combo), false);

    //console.log('+++++ ' + isAllowed + ' ' + combo);

    if (!isAllowed) {
      end403({req, res, err: 'Не разрешено для архивов', log});
      return true;
    }

    // разрешаем доступ без авторизации
    let isPublic = [
      /^get mdm\//,
    ].reduce((a, re) => a || re.test(combo), false);

    if (!isPublic) {
      // проверяем авторизацию локально
      var user;
      try { user = await auth(req, res) } catch(err) {
        end401({req, res, err:'Неверный логин/пароль', log});
        return true;
      }

      if (
        !user || !user.roles || !user.acl_objs || 
        !user.roles.includes('doc_full') &&
        !user.roles.includes('_admin') &&
        !user.acl_objs._obj.some(r => r.type == 'ПросмотрАрхивов')
      ) {
        end401({req, res, err: paths.join('/'), log});
        return true;
      }
    }

    const un = conf.user_node,
          authToken = conf.archive_node.authorization || Buffer.from(`${un.username}:${un.password}`).toString('base64'),
          proxy_server = proxy[yrow.proxy.startsWith('https://') ? 'https' : 'http'];

    req.headers.authorization = 'Basic ' + authToken;
    delete req.headers.year;

    proxy_server.web(req, res, {target: yrow.proxy});
    
    return true;
  }
}