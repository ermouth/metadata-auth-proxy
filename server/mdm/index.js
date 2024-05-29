/**
 * ### Обрабатывает запросы /mdm/
 * Возвращает обрезанную ram
 *
 * @module get
 *
 * Created by Evgeniy Malyarov on 05.02.2019.
 */

const {end404, end500} = require('../http/end');
const fs = require('fs');
const {resolve} = require('path');
const merge2 = require('merge2');
const manifest = require('./manifest');
const head = require('./head');
const current_branch = require('./current_branch');
require('../http/promisify');

// эти режем по отделу
const by_branch = [
  'cat.partners',
  'cat.contracts',
  'cat.branches',
  'cat.divisions',
  'cat.users',
  'cat.individuals',
  'cat.organizations',
  'cat.cashboxes',
  'cat.stores',
  'cch.predefined_elmnts',
];
// эти общие - их не режем и грузим сразу
const common = [
  'cch.properties',
  'cat.abonents',
  'cat.price_groups',
  'cat.property_values',
  'cat.property_values_hierarchy',
  'cat.contact_information_kinds',
  'cat.cash_flow_articles',
  'cat.clrs',
  'cat.color_price_groups',
  'cat.delivery_areas',
  'cat.delivery_directions',
  'cat.units',
  'cat.countries',
  'cat.currencies',
  'cat.scheme_settings',
  'cat.meta_ids',
  'cat.destinations',
  'cat.nom_groups',
  'cat.nom_kinds',
  'cat.elm_visualization',
  'cat.templates',
  'cat.http_apis',
  'cat.work_center_kinds',
  'cat.work_centers',
  'cat.stages',
  'cat.project_categories',
  'cat.lead_src',
];

function mdm ($p, log) {

  const {md, cat: {branches, templates, users}, utils, job_prm, adapters: {pouch}} = $p;
  // порядок загрузки, чтобы при загрузке меньше оборванных ссылок
  const load_order = order(md);

  return async (req, res) => {
    const {query, path, paths} = req.parsed;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');

    try{
      const {user, parsed: {query, path, paths}, headers} = req;
      const zone = paths[2];
      let suffix = paths[3];
      let branch = user && user.branch;

      const {abonents} = job_prm.server;
      if(!abonents.some((id) => id == zone)) {
        return end500({req, res, err: {status: 406, message: `Текущий proxy обслуживает зоны ${abonents.join(', ')}, но запрошена зона ${zone}`}, log});
      }

      if(suffix === 'templates') {
        // возвращаем характеристики шаблона
        const fname = resolve(__dirname, `./cache/${zone}/0000/doc.calc_order.${paths[4]}.json`);
        const mname = fname.replace('.json', '.manifest');
        const mtext = fs.existsSync(mname) && await fs.readFileAsync(mname, 'utf8');
        res.setHeader('manifest', mtext || '');
        if(req.method === 'HEAD') {
          res.end();
        }
        else if(!fs.existsSync(fname)) {
          return end404(res, fname);
        }
        else {
          const stream = fs.createReadStream(fname);
          stream.pipe(res);
          res.on('close', () => stream.destroy());
        }
        return;
      }
      else if(branch && !branch.empty() && suffix !== 'common') {
        suffix = branch.suffix;
      }
      else if(suffix && (!branch || branch.empty())) {
        branches.find_rows({suffix}, (o) => {
          branch = o;
          return false;
        });
      }
      if(!suffix) {
        suffix = '0000';
      }
      if(!branch) {
        branch = branches.get();
      }

      // если данные не общие, проверяем пользователя
      if(suffix !== 'common' && !user) {
        return end500({req, res, err: {status: 403, message: 'Пользователь не авторизован'}, log});
      }

      // дополнительные маршруты
      if(paths[4] === 'prices') {

      }

      if(req.method === 'HEAD') {
        return await head({res, zone, suffix, by_branch, common});
      }

      // проверяем наличие каталога
      if(!fs.existsSync(resolve(__dirname, `./cache/${zone}/${suffix === 'common' ? '0000' : suffix}`))) {
        return end404(res, `/couchdb/mdm/${zone}/${suffix === 'common' ? '0000' : suffix}`);
      }
      // пишем манифест в head
      await manifest({res, zone, suffix, by_branch, common});

      const tags = {};
      const stream = merge2();
      const types = headers.types ? headers.types.split(',') : null;
      for(const names of load_order) {
        for(const name of names) {
          // если запросили определенные типы данных, возвращаем только их
          if(types && !types.includes(name)) {
            continue;
          }
          const mgr = md.mgr_by_class_name(name);
          if(mgr) {
            const fname = suffix === 'common' ?
              resolve(__dirname, `./cache/${zone}/0000/${name}.json`)
              :
              resolve(__dirname, `./cache/${zone}/${by_branch.includes(name) ? suffix : '0000'}/${name}.json`);

            if(suffix === 'common' && !common.includes(name)) {
              continue;
            }
            if(suffix !== 'common' && common.includes(name)) {
              continue;
            }
            // если файл существует, добавляем его в поток
            fs.existsSync(fname) && stream.add(fs.createReadStream(fname));
          }
        }
      }
      suffix === 'common' && current_branch({stream, branches, users, headers, utils});
      stream.pipe(res);
      res.on('close', () => stream.destroy());
    }
    catch(err){
      end500({req, res, err, log});
    }

  };
}

function order (md) {
  const res = [
    new Set(['cch.properties']),
    new Set(),
    new Set(),
    new Set(),
    new Set(),
    new Set(),
    new Set(['cch.predefined_elmnts', 'ireg.currency_courses', 'ireg.margin_coefficients', 'doc.calc_order'])
  ];

  for(const class_name of md.classes().cat) {
    if(['servers', 'nom_units', 'meta_fields', 'meta_objs', 'contracts', 'partner_bank_accounts'].includes(class_name)) {
      continue;
    }
    else if(['abonents', 'property_values', 'property_values_hierarchy', 'contact_information_kinds', 'currencies'].includes(class_name)) {
      res[1].add(`cat.${class_name}`);
    }
    else if(class_name === 'users') {
      res[2].add(`cat.${class_name}`);
    }
    else if(class_name.includes('nom')) {
      res[3].add(`cat.${class_name}`);
    }
    else if(class_name === 'formulas') {
      res[5].add(`cat.${class_name}`);
    }
    else if(class_name === 'choice_params') {
      res[6].add(`cat.${class_name}`);
    }
    else{
      res[4].add(`cat.${class_name}`);
    }
  }

  return res;
}

mdm.by_branch = by_branch;
mdm.order = order;
mdm.common = common;

module.exports = mdm;
