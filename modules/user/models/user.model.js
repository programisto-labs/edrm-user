import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: false,
    select: false // Password won't be returned in queries by default
  },
  firstname: {
    type: String,
    required: true,
  },
  lastname: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    get: function() {
      return this._name || `${this.firstname} ${this.lastname}`;
    },
    set: function(value) {
      this._name = value;
    }
  },
  role: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
  },
  refreshToken: {
    type: String,
    default: null,
  },
  resetToken: {
    type: String,
    default: null,
  },
  resetTokenExpiration: {
    type: Date,
    default: null,
  },
}, {
  timestamps: true, // Ajoute les champs createdAt et updatedAt automatiquement
});

// Middleware pour hacher le mot de passe avant de sauvegarder l'utilisateur
userSchema.pre('save', async function (next) {
  if (this.isModified('password') || (this.isNew && this.password)) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Méthode pour comparer le mot de passe
userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Méthode pour réinitialiser le refresh token
userSchema.methods.resetRefreshToken = function () {
  this.refreshToken = null;
  return this.save();
};

const User = mongoose.model('User', userSchema, 'users');

export default User;
