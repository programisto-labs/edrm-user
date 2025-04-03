import { EnduranceSchema, EnduranceModelType, EnduranceDocumentType } from 'endurance-core';
import bcrypt from 'bcrypt';
import Role from './role.model.js';

@EnduranceModelType.pre<User>('save', async function (this: EnduranceDocumentType<User>, next: (err?: Error) => void) {
  if (this.isModified('password') || (this.isNew && this.password)) {
    const hashedPassword = await bcrypt.hash(this.password!, 10);
    this.password = hashedPassword;
  }
  next();
})

class User extends EnduranceSchema {
  @EnduranceModelType.prop({
    required: true,
    unique: true,
    default: async function () {
      const lastUser = await UserModel.findOne().sort({ id: -1 }).exec();
      return lastUser ? lastUser.id + 1 : 1;
    }
  })
  public id!: number;

  @EnduranceModelType.prop({ required: true, unique: true })
  email!: string;

  @EnduranceModelType.prop({ required: false, select: false })
  password?: string;

  @EnduranceModelType.prop({ required: true })
  firstname!: string;

  @EnduranceModelType.prop({ required: true })
  lastname!: string;

  @EnduranceModelType.prop()
  private _name?: string;

  @EnduranceModelType.prop({ ref: () => Role })
  role?: typeof Role;

  @EnduranceModelType.prop({ default: null })
  refreshToken?: string;

  @EnduranceModelType.prop({ default: null })
  resetToken?: string;

  @EnduranceModelType.prop({ default: null })
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

  public static getModel() {
    return UserModel;
  }
}

const UserModel = EnduranceModelType.getModelForClass(User);
export default UserModel;
