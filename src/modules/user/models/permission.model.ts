import { EnduranceSchema, EnduranceModelType } from 'endurance-core';

class Permission extends EnduranceSchema {
  @EnduranceModelType.prop({ required: true, unique: true })
  public name!: string;

  @EnduranceModelType.prop()
  public description?: string;

  public static getModel() {
    return PermissionModel;
  }
}

const PermissionModel = EnduranceModelType.getModelForClass(Permission);
export default PermissionModel;
