import { EnduranceSchema, EnduranceModelType, EnduranceDocumentType } from '@programisto/endurance-core';
import bcrypt from 'bcrypt';
import Role from './role.model.js';
import { UserType } from '../../../types/user.js';
import { RoleType } from '../../../types/role.js';

class User extends EnduranceSchema implements UserType {
  @EnduranceModelType.prop({
    required: false,
    unique: true,
    get: function (this: any) {
      return this.id || this.uid;
    }
  })
  public id!: number;

  // Garder uid pour la rétrocompatibilité
  @EnduranceModelType.prop({
    required: false
  })
  public uid?: number;

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
  roles?: RoleType[];

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

EnduranceModelType.pre<User>('save', async function (this: EnduranceDocumentType<User>, next: (err?: Error) => void) {
  if (this.isModified('password') || (this.isNew && this.password)) {
    const hashedPassword = await bcrypt.hash(this.password!, 10);
    this.password = hashedPassword;
  }

  if (!this.id && (this as any).uid) {
    this.id = (this as any).uid;
  }

  if (!this.id) {
    const lastUser = await UserModel.findOne().sort({ id: -1 });
    this.id = lastUser ? lastUser.id + 1 : 1;
  }
  next();
});

const UserModel = EnduranceModelType.getModelForClass(User);
export default UserModel;
