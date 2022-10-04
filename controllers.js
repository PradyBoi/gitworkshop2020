const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const con = require('./../db_connection.js');
const sendEmail = require('./../email');

const signToken = (id, expireTime = '30000') => {
  console.log(expireTime);
  return jwt.sign({ id: id }, process.env.SECRET, {
    expiresIn: expireTime,
  });
};

const refreshTokenFun = (id) => {
  return jwt.sign({ id }, process.env.REFRESHTOKEN, {
    expiresIn: '1d',
  });
};

const passwordDoesNotMatch = async (
  enteredPassword,
  savedPassword,
  savedSalt
) => {
  const hashedPassword = await bcrypt.hash(enteredPassword, savedSalt);
  if (savedPassword !== hashedPassword) return true;
  return false;
};

const getQuotesFun = async (id) => {
  return await con.query_prom(
    'SELECT Quote FROM Quotes WHERE Owner=? AND isDeleted=?',
    [id, 0]
  );
};

// Returns sugesstions in a STRING!
const strongPassword = async (password, passwordConfirm) => {
  // if the password is NOT confirmed!
  if (password !== passwordConfirm) {
    return 'Password does not match. Please try again!';
  }

  const specialChar = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;

  // Checking for strong password
  if (!specialChar.test(password)) {
    return 'Password must contain a special character';
  }

  if (!(password.length >= 8)) {
    return 'Password must be 8 characters long';
  }

  if (password.search(/[0-9]/) == -1) {
    return 'Password must contain 1 Numeric character';
  }

  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    return 'Password must contain 1 UpperCase and 1 LowerCase character';
  }
};

exports.refreshToken = (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token)
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in. Please login again.',
      });

    // TOKEN Verification
    const { id } = jwt.verify(token, process.env.REFRESHTOKEN);

    res.cookie('accessToken', signToken(id), {
      httpOnly: true,
    });
    res.cookie('refreshToken', refreshTokenFun(id), {
      httpOnly: true,
    });

    return res.status(200).json({
      status: 'success',
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({
        status: 'fail',
        message: 'Your token has expired!. Please try logging in again.',
      });
    if (err.name === 'JsonWebTokenError')
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token! Please try logging in again.',
      });
  }
};

const storeHasedPassword = async (email, password) => {
  const salt = await bcrypt.genSalt();
  const hashed = await bcrypt.hash(password, salt);

  await con.query_prom('UPDATE users SET salt=?, Password=? WHERE Email=?', [
    salt,
    hashed,
    email,
  ]);
};

exports.registerNewUser = async (req, res) => {
  try {
    const { name, email, password, passwordConfirm } = req.body;

    // Retreiving email from DB
    const queryRes = await con.query_prom(
      'SELECT Email FROM users WHERE Email=?',
      [email]
    );

    // if Email exists
    if (!(queryRes.length === 0)) {
      const [{ Email }] = JSON.parse(JSON.stringify(queryRes));

      // Checking if provided email exists in DB
      if (Email.toLowerCase() === email.toLowerCase()) {
        return res.status(400).json({
          status: 'fail',
          message: 'This email is already registered!',
        });
      }
    }

    // if it's a Strong Password
    const string = await strongPassword(password, passwordConfirm);

    if (string) {
      return res.status(400).json({
        status: 'Bad request',
        message: string,
      });
    }

    // Registering New User!
    const { insertId: id } = await con.query_prom(
      'INSERT INTO users (Name, Email) VALUES (?,?);',
      [name, email]
    );

    try {
      await storeHasedPassword(email, password);
    } catch (err) {
      if (err) console.log(err);

      return res.status(500).json({
        status: 'Internal server error',
        message: 'There was an error sending the email. Try again later!',
      });
    }

    // Getting new Access & Refresh Token
    const token = signToken(id);
    const refToken = refreshTokenFun(id);

    // Sending cookies
    res.cookie('accessToken', token, {
      httpOnly: true,
    });
    res.cookie('refreshToken', refToken, {
      httpOnly: true,
    });

    // Sending response to client
    res.status(201).json({
      status: 'success',
      message: 'User created!',
    });
  } catch (err) {
    // if (err) {
    return res.status(500).json({
      status: 'fail',
      error: err.message,
    });
    // }
  }
};

exports.login = async (req, res) => {
  const { Email: userEmail, Password: userPassword } = req.body;

  if (!userEmail || !userPassword) {
    return res.status(400).json({
      status: 'Bad request',
      message: 'Please provide the email and password',
    });
  }

  const resultVal = await con.query_prom(
    'SELECT Name, Email, Password, userID, salt FROM users WHERE Email=?',
    [userEmail]
  );

  const [filterResults] = JSON.parse(JSON.stringify(resultVal));

  // if user DOES NOT exist || password DOES NOT exits, RETURN 'Bad request'
  if (
    !filterResults ||
    (await passwordDoesNotMatch(
      userPassword,
      filterResults.Password,
      filterResults.salt
    ))
  )
    return res.status(400).json({
      status: 'Bad request',
      message: 'Incorrect email or password',
    });

  const [{ requestCounter, requestCounterExpires }] = await con.query_prom(
    'SELECT requestCounter, requestCounterExpires FROM users WHERE userID=?',
    [filterResults.userID]
  );

  const expiryDate = new Date(requestCounterExpires);

  // CHECK if user has exceeded the login limit and 24 hours has passed.
  if (requestCounter === 1 && expiryDate.getTime() > Date.now()) {
    return res.status(401).json({
      status: 'Forbidden',
      message:
        'You have exceed the maximum limit allowed to login. Try again after 24 hours, or reset password',
    });
  }

  if (req.rateLimit.limit === req.rateLimit.current) {
    // When user exceeds login attempts, SET requestCounter = 1 in SQL
    await con.query_prom(
      'UPDATE users SET requestCounter=?, requestCounterExpires=? WHERE userID=?',
      [1, new Date(Date.now() + 24 * 60 * 60 * 1000), filterResults.userID]
    );
  }

  const token = signToken(filterResults.userID);
  const refToken = refreshTokenFun(filterResults.userID);

  res.cookie('accessToken', token, {
    httpOnly: true,
  });
  res.cookie('refreshToken', refToken, {
    httpOnly: true,
  });

  res.status(200).json({
    status: 'success',
    message: 'Logged In!',
  });
};
// ---------------------------------------DONE---------------------------------------------

exports.logout = (_, res) => {
  res.clearCookie('refreshToken');
  res.clearCookie('accessToken');
  return res.status(200).json({
    status: 'success',
    message: 'Logged Out!',
  });
};

// checkId function
exports.checkId = async (req, res, next) => {
  const reqId = req.params.id * 1;
  if (reqId < 1 || !Number.isInteger(reqId)) {
    return res.status(404).json({
      status: 'Bad Request',
      message: 'Invalid Id',
    });
  }
  next();
};

// Controllers
exports.getQuotes = (_, res) => {
  res.json(res.paginatedResults);
};

exports.getMyQuotes = async (req, res) => {
  try {
    const myQuote = await getQuotesFun(req.id);

    if (myQuote.length === 0) {
      return res.status(200).json({
        message: 'You have no quotes yet.',
      });
    }

    res.status(200).json({
      status: 'success',
      yourQuotes: myQuote,
    });
  } catch (err) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid Id. Please enter the correct Id.',
    });
  }
};

exports.getQuotesOfTheUser = async (req, res, next) => {
  try {
    const { userID: id } = req.body;
    const myQuote = await getQuotesFun(id);

    res.status(200).json({
      status: 'success',
      id,
      yourQuotes: myQuote,
    });
  } catch (err) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid Id. enter the correct Id.',
    });
  }

  next();
};

exports.postQuote = async (req, res) => {
  const data = req.body;

  await con.query_prom(
    `INSERT INTO Quotes (Quote, Author, Owner) VALUES (?,?,?)`,
    [data.Quote, data.Author, req.id]
  );

  res.status(201).json({
    status: 'success',
    message: 'Your Quote has been posted!',
  });
};

exports.deleteQuotes = async (req, res) => {
  const Id = req.params.id * 1;

  const Owners = await con.query_prom(
    'SELECT Owner FROM Quotes WHERE Id=? AND isDeleted=?',
    [Id, 0]
  );
  if (!Owners)
    return res.status(404).json({
      status: 'fail',
      message: 'Owner not found',
    });
  const [owner] = Owners.map((owner) => owner.Owner);
  if (owner !== req.id) {
    return res.status(400).json({
      status: 'fail',
      message:
        'This Quote does not belong to you. Please delete the quote that you own.',
    });
  }
  const { affectedRows } = await con.query_prom(
    'UPDATE Quotes SET isDeleted=? WHERE Id=?',
    [1, Id]
  );
  res.status(200).json({
    status: 'success',
    message: 'data deleted',
    data: {
      affectedRows,
    },
  });
};

exports.protect = async (req, res, next) => {
  try {
    // if the token is provided in the cookie
    if (!req.cookies.accessToken) {
      return res.status(401).json({
        status: 'Unauthorized',
        message: 'You are not logged in! Please log in to get access.',
      });
    }

    // verify token
    const { id } = jwt.verify(req.cookies.accessToken, process.env.SECRET);
    req.id = id;
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({
        status: 'fail',
        message: 'Your token has expired!. Please try logging in again.',
      });
    if (err.name === 'JsonWebTokenError')
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token! Please try logging in again.',
      });
  }

  next();
};

exports.forgotPassword = async (req, res) => {
  // 1. get user based on POSTED emails
  const resultVal = await con.query_prom(
    'SELECT Email, Password, userID, salt FROM users WHERE Email=?',
    [req.body.Email]
  );

  const [filterResults] = JSON.parse(JSON.stringify(resultVal));

  if (!req.body.Email || !req.body.Password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide email and password.',
    });
  }
  if (
    !filterResults ||
    (await passwordDoesNotMatch(
      req.body.Password,
      filterResults.Password,
      filterResults.salt
    ))
  ) {
    return res.status(400).json({
      status: 'fail',
      message: 'Incorrect email or password.',
    });
  }

  const resetToken = signToken(filterResults.userID, `${10 * 60 * 1000}`);

  console.log(resetToken);

  // 3. send it to user's email
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/resetPassword/${resetToken}`;

  const message = `Forgot your password? Send a request to with your new password and confirmPassword to:${resetURL}.\nIf you didn't forgot your password, then ignore this email`;

  try {
    await sendEmail({
      email: req.body.Email,
      subject: 'Your password reset token (valid only for 10 minutes)',
      message,
    });
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (err) {
    if (err) console.log(err);

    return res.status(500).json({
      status: 'Internal server error',
      message: 'There was an error sending the email. Try again later!',
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const resetToken = req.params.token;

    // NOT WORKING [CHECK]
    if (!resetToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Please provide a token to reset your password.',
      });
    }

    const { id } = jwt.verify(resetToken, process.env.SECRET);

    if (!req.body.Password || !req.body.PasswordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a password, and confirm the password.',
      });
    }

    const [{ Email, Password, salt }] = await con.query_prom(
      'SELECT Email, Password, salt FROM users WHERE userID=?',
      [id]
    );

    if (!(await passwordDoesNotMatch(req.body.Password, Password, salt))) {
      return res.status(400).json({
        status: 'fail',
        message:
          'Old password matches with the new password. Please try enter a new unique password!',
      });
    }

    if (req.body.Password !== req.body.PasswordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Password does not match! Please try again.',
      });
    }

    await storeHasedPassword(Email, req.body.Password);

    return res.status(200).json({
      status: 'success',
      message: 'Password updated successfully!',
    });
  } catch (err) {
    if (err) console.log(err.message);
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({
        status: 'fail',
        message: 'Your token has expired!. Please try logging in again.',
      });
    if (err.name === 'JsonWebTokenError')
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token! Please try logging in again.',
      });
  }
};
