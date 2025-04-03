import { EnduranceSchema, EnduranceModelType } from 'endurance-core';
import Permission from './permission.model.js';

class Role extends EnduranceSchema {
  @EnduranceModelType.prop({
    required: true,
    unique: true,
    default: async function () {
      const lastRole = await RoleModel.findOne().sort({ id: -1 }).exec();
      return lastRole ? lastRole.id + 1 : 1;
    }
  })
  public id!: number;

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
