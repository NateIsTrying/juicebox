const { getUserById } = require('../db/index');
const jwt = require('jsonwebtoken');
const { JTW_SECRET } = process.env;

const requireUser = async(req, res, next) => {
  try {
    const authHeader = req.header('Authorization');

    if(!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'You must be logged in to do that.' });
    }

    const token = authHeader.slice('Bearer '.length);
    
    try {
      const { id } = jwt.verify(token, JWT_SECRET);
    
      if(!id) {
        return res.status(401).json({ error: 'Invalid token.' });
      }

      const user = await getUserById(id);
      if(!user) {
        return res.status(401).json({ error: 'User not found.' });
      }

      req.user = user;
      next();
    } catch (error) {
      console.log('Error verifying token:', error);
      return res.status(401).json({ error: 'Invalid token.' });
    }
  } catch(error) {
    console.log('Error in requireUser middleware:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = {
  requireUser,
};