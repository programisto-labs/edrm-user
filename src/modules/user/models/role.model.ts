import { EnduranceSchema, prop, Ref } from "endurance-core";
import Permission from "./permission.model.js";

class Role extends EnduranceSchema {
  @prop({ required: true, unique: true })
  public name!: string;

  @prop({ ref: () => Permission })
  public permissions?: Ref<typeof Permission>[];
}

export default Role.getModel();
