import { EnduranceSchema, EnduranceModelType } from '@programisto/endurance';
import Permission from './permission.model.js';

class Role extends EnduranceSchema {
  @EnduranceModelType.prop({ required: true, unique: true })
  public name!: string;

  @EnduranceModelType.prop({ ref: () => Permission })
  public permissions?: typeof Permission[];

  public static getModel() {
    return RoleModel;
  }
}

const RoleModel = EnduranceModelType.getModelForClass(Role);
export default RoleModel;
