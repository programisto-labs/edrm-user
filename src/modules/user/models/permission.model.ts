import { EnduranceSchema, prop } from "endurance-core";

class Permission extends EnduranceSchema {
  @prop({ required: true, unique: true })
  public name!: string;

  @prop()
  public description?: string;
}

export default Permission.getModel();
