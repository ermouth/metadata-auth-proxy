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

  proxyThisYear = conf.archive_node.proxyThisYear;

  return async function proxy_by_year(req, res) {
    const {year, zone} = req.headers;
    if (!zone) return;

    const key = parseFloat(year) || conf.server.year,
          abonent = abonents.by_id(zone);
    if(abonent.is_new()) return;
    if(key == conf.server.year && !proxyThisYear) return;

    var yrow = abonent.servers.find({key});
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
      end403({req, res, err: 'Метод не разрешен для архива.', log});
      return true;
    }

    // разрешаем по путям
    let isAllowed = [
      /^get /,
      /^post auth\/couchdb/,
      /^post [a-z]+_\d+_(doc|ram)\/_(all_docs|find|bulk_get)/,
      /^post [a-z]+_\d+_doc\/doc\.calc_order/,
    ].reduce((a, re) => a || re.test(combo), false);

    //console.log('+++++ ' + isAllowed + ' ' + combo);

    if (!isAllowed) {
      end403({req, res, err: 'Не разрешено для архивов.', log});
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
        end401({req, res, err:'Неверный логин/пароль.', log});
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
          an = conf.archive_node,
          authToken = an.authorization || Buffer.from(`${un.username}:${un.password}`).toString('base64');

    req.headers.authorization = 'Basic ' + authToken;

    if (an.proxies && an.proxies[zone]) {
      // Режим киоска, 
      // идём на auth-proxy зоны текущего года, год не сбрасываем
      yrow = { proxy: an.proxies[zone] };
    } 
    else {
      // идём прямо на auth-proxy архива, сбрасываем год
      delete req.headers.year;
    }

    const proxy_server = proxy[yrow.proxy.startsWith('https://') ? 'https' : 'http'];
    proxy_server.web(req, res, {target: yrow.proxy});
    
    return true;
  }
}