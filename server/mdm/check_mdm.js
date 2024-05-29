const dyn_mdm = require('./dyn_mdm');
const {common} = require('./index');

module.exports = function check_mdm({o, name, abonent, branch, abranches, job_prm}) {

  if(!o) {
    return false;
  }

  const zone = abonent.id;
  const {_obj} = o;

  if(name === 'cat.characteristics') {
    return check_characteristics(o);
  }
  if(common.includes(name)) {
    if(name === 'cat.clrs') {
      return o.ref && o.name && o.name !== ' \\ ';
    }
    return name === 'cat.abonents' ? job_prm.server.abonents.includes(o.id) : true;
  }
  else if(name === 'doc.calc_order') {
    return check_calc_order(o);
  }
  else if(name === 'cch.predefined_elmnts' || name === 'cat.formulas') {
    return !o.disabled && (o.context !== 2);
  }

  if(abonent.no_mdm && branch.empty() || branch.no_mdm || job_prm.server.no_mdm) {
    return true;
  }

  if(branch.empty()) {
    if(name === 'cat.users') {
      return o.subscribers.find({abonent});
    }
    else if(name === 'cat.branches') {
      return o.owner == abonent || o._children().some((branch) => branch.owner == abonent);
    }
  }
  else {
    if(name === 'cat.users') {
      return o.branch.empty() ? o.subscribers.find({abonent}) : (o.branch == branch || o.branch.parent == branch);
    }
    else if(name === 'cat.branches') {
      return o._hierarchy(branch) || branch._parents().includes(o);
    }
  }
  if(name === 'cat.partners') {
    const rows = o.is_folder ? o._children().concat(o) : [o];
    return rows.some((acl_obj) => abranches.some((branch) => branch.partners.find({acl_obj})));
  }
  else if(name === 'cat.organizations') {
    return abranches.some((branch) => branch.organizations.find({acl_obj: o}));
  }
  else if(name === 'cat.divisions') {
    const rows = o._children().concat(o);
    return rows.some((acl_obj) => abranches.some((branch) => branch.divisions.find({acl_obj})));
  }
  else if(name === 'cat.cashboxes' || name === 'cat.stores') {
    const rows = o.department._children().concat(o.department);
    return rows.some((acl_obj) => abranches.some((branch) => branch.divisions.find({acl_obj})));
  }

  return dyn_mdm.check(o);
}


function check_characteristics(o) {
  return o.calc_order.empty();
  // if(!check_characteristics.cache) {
  //   check_characteristics.cache = new Set();
  //   o._manager._owner.templates.forEach((template) => {
  //     template.templates.forEach(({template}) => {
  //       check_characteristics.cache.add(template);
  //     });
  //   });
  // }
}

function check_calc_order(o) {
  if(o.obj_delivery_state != 'Шаблон') return false;
  return dyn_mdm.templates.has(o);
}
