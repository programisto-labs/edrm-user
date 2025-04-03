import { EnduranceSchema, EnduranceModelType } from 'endurance-core';

class Permission extends EnduranceSchema {
  @EnduranceModelType.prop({
    required: true,
    unique: true,
    default: async function () {
      const lastPermission = await PermissionModel.findOne().sort({ id: -1 }).exec();
      return lastPermission ? lastPermission.id + 1 : 1;
    }
  })
  public id!: number;

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
