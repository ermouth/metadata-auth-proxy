/**
 *
 *
 * @module 404
 *
 * Created by Evgeniy Malyarov on 04.06.2019.
 */

function end(res, body) {
  if(!res.finished) {
    if(res.headersSent) {
      res.statusCode = body.status;
      res.write(JSON.stringify(body));
      res.end();
    }
    else {
      res.statusCode = body.status;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(body));
    }
  }
}

function ip({req, res, err}) {
  if(req) {
    err.ip = `${req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || res.socket.remoteAddress}`;
  }
  return [err, 'error'];
}

module.exports = {
  end401({req, res, err, log}) {
    log(...ip({req, res, err}));
    end(res, {
      error: true,
      status: 401,
      message: `Запрос не авторизован ${err.stack || err.message || ''}`,
    });

  },
  end403({req, res, err, log}) {
    log(...ip({req, res, err}));
    end(res, {
      error: true,
      status: 403,
      message: typeof err == 'string' ? err : `Не разрешено '${req.method} ${req.url}'`,
    });
  },
  end404(res, path) {
    end(res, {
      error: true,
      status: 404,
      message: `Путь '${path}' не существует`,
    });
  },
  end500({req, res, err, log}) {
    log(...ip({req, res, err}));
    end(res, {
      error: true,
      status: err.status || 500,
      message: err.message || 'Ошибка сервера',
    });
  }
};
