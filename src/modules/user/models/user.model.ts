import { EnduranceSchema, prop, pre, Ref } from "endurance-core";
import bcrypt from 'bcrypt';
import Role from './role.model.js';

@pre<User>('save', async function (next) {
  if (this.isModified('password') || (this.isNew && this.password)) {
    const hashedPassword = await bcrypt.hash(this.password!, 10);
    this.password = hashedPassword;
  }
  next();
})

class User extends EnduranceSchema {
  @prop({ required: true, unique: true })
  email!: string;

  @prop({ required: false, select: false })
  password?: string;

  @prop({ required: true })
  firstname!: string;

  @prop({ required: true })
  lastname!: string;

  @prop()
  private _name?: string;

  @prop({ ref: () => Role })
  role?: Ref<typeof Role>;

  @prop({ default: null })
  refreshToken?: string;

  @prop({ default: null })
  resetToken?: string;

  @prop({ default: null })
  resetTokenExpiration?: Date;

  get name(): string {
    return this._name || `${this.firstname} ${this.lastname}`;
  }

  set name(value: string) {
    this._name = value;
  }

  comparePassword(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password || '');
  }

  async resetRefreshToken(): Promise<this> {
    this.refreshToken = undefined;
    return this.save();
  }

  save!: () => Promise<this>;
}

export default User.getModel();
