const bcrypt = require("bcrypt");
module.exports = class User {
  constructor({
    utils,
    cache,
    config,
    cortex,
    managers,
    validators,
    oyster,
  } = {}) {
    this.utils = utils;
    this.config = config;
    this.cortex = cortex;
    this.validators = validators;
    this.oyster = oyster;
    this.tokenManager = managers.token;
    this.shark = managers.shark;
    this.responseDispatcher = managers.responseDispatcher;
    this.usersCollection = "users";
    this.userPrefix = "user";
    this.httpExposed = [
      "createUser",
      "loginUser",
      "patch=updateUser",
      "delete=deleteUser",
      "get=getUser",
    ];
    this.userExposed = ["createUser"];
  }
  async _hashPassword(password) {
    return bcrypt.hash(password, 10);
  }
  async _verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }
  async _loadPermissions({ userId, role }) {
    const addDirectAccess = ({ nodeId, action }) => {
      return this.shark.addDirectAccess({
        userId,
        nodeId,
        action,
      });
    };
    const lookupTable = {
      schoolAdmin: async () => {
        const items = [
          {
            nodeId: "board.school",
            action: "read",
          },
          {
            nodeId: "board.school.class",
            action: "update",
          },
          {
            nodeId: "board.school.class.student",
            action: "update",
          },
        ];
        for (const item of items) {
          await addDirectAccess(item);
        }
      },
      superadmin: async () => {
        const items = [
          {
            nodeId: "board.school",
            action: "update",
          },
          {
            nodeId: "board.school.class",
            action: "config",
          },
          {
            nodeId: "board.school.class.student",
            action: "config",
          },
          {
            nodeId: "board.user",
            action: "config",
          },
        ];
        for (const item of items) {
          await addDirectAccess(item);
        }
      },
    };
    if (lookupTable[role]) {
      await lookupTable[role]();
    }
  }
  async createUser({ username, email, password, role = "student", res }) {
    const user = { username, email, password, role };

    // Data validation
    const result = await this.validators.user.createUser(user);
    if (result) return result;

    // Creation Logic
    let createdUser = {
      _id: email,
      _label: this.userPrefix,
      username,
      email,
      password: this._hashPassword(password),
      role,
      createdAt: Date.now(),
    };
    const userCreated = await this.oyster.call("add_block", createdUser);
    if (userCreated.error) {
      if (userCreated.error.includes("already exists")) {
        this.responseDispatcher.dispatch(res, {
          code: 409,
          message: `User with email ${email} already exists`,
        });
        return { selfHandleResponse: true };
      }
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 500,
        message: "Failed to create user",
      });
      return { selfHandleResponse: true };
    }
    await this._loadPermissions({ userId: createdUser._id, role });

    delete userCreated.password;
    // Response
    return {
      user: userCreated,
      longToken: this.tokenManager.genLongToken({
        userId: createdUser._id,
        userKey: userCreated.key,
      }),
    };
  }
  async loginUser({ email, password, res }) {
    const result = await this.validators.user.loginUser({ email, password });
    if (result) return result;
    const user = await this.oyster.call(
      "get_block",
      `${this.userPrefix}:${email}`,
    );
    if (!user || this.utils.isEmptyObject(user)) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 404,
        message: "Invalid user login",
      });
    }
    if (!(await this._verifyPassword(password, user.password))) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 404,
        message: "Invalid user login",
      });
    }
    delete user.password;
    return {
      user: user,
      longToken: this.tokenManager.genLongToken({
        userId: email,
        userKey: user.key,
      }),
    };
  }
  async updateUser({ __token, id, username, email, password, res }) {
    const { userId } = __token;
    if (role) {
      //superadmin is require to update roles field
      if (
        !(await this.shark.isGranted({
          layer: "board.user",
          action: "config",
          userId,
          nodeId: `board.user.${id}`,
          role: "superadmin",
        }))
      ) {
        this.responseDispatcher.dispatch(res, {
          ok: false,
          code: 403,
          message: "Private fields only accessable by superadmin",
        });
      }
    }
    const result = this.validators.user.updateUser({
      username,
      email,
      password,
      role,
    });
    if (result) return result;
    const user = await this.oyster.call(
      "get_block",
      `${this.userPrefix}:${id}`,
    );
    if (!user || this.utils.isEmptyObject(user)) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 404,
        message: "User not found",
      });
      return { selfHandleResponse: true };
    }
    let updates = Object.create();
    if (username) updates.username = username;
    if (email) updates.email = email;
    if (password) updates.password = await this._hashPassword(password);
    if (role) {
      updates.role = role;
      // Reload permission when role update
      await this._loadPermissions({ userId: id, role });
    }
    updates.updatedAt = Date.now();
    updates.updatedBy = userId;
    const updatedUser = await this.oyster.call("update_block", {
      _id: `${this.userPrefix}:${id}`,
      ...updates,
    });
    delete updatedUser.password;
    return { user: updatedUser };
  }
  async deteleUser({ __token, id, res }) {
    const { userId } = __token;
    // Validate superadmin before delete actions
    if (
      !(await this.shark.isGranted({
        layer: "broad.user",
        action: "delete",
        userId,
        nodeId: `board.user.${id}`,
        role: "superadmin",
      }))
    ) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 403,
        message: "Private action require superadmin role",
      });
      return { selfHandleResponse: true };
    }
    const user = await this.oyster.call(
      "get_block",
      `${this.userPrefix}:${id}`,
    );
    if (!user || this.utils.isEmptyObject(user)) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 404,
        message: "User not found",
      });
      return { selfHandleResponse: true };
    }
    await this.oyster.call("delete_block", `${this.userPrefix}:${id}`);
    await this.oyster.call("delete_relations", {
      _id: `${this.userPrefix}:${id}`,
    });
    return { message: "User deleted successfully" };
  }
  async getUser({ __token, id, res }) {
    const { userId } = __token;
    const canViewUser =
      (await this.shark.isGranted({
        layer: "board.user",
        action: "read",
        userId,
        nodeId: `board.user.${id}`,
        role: "superadmin",
      })) || userId === id;
    if (!canViewUser) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 403,
        message: "You don't have permission to view this fields",
      });
      return { selfHandleResponse: true };
    }
    const user = await this.oyster.call(
      "get_block",
      `${this.userPrefix}:${id}`,
    );
    if (!user || this.utils.isEmptyObject(user)) {
      this.responseDispatcher.dispatch(res, {
        ok: false,
        code: 404,
        message: "User not found",
      });
      return { selfHandleResponse: true };
    }
    delete user.password;
    return { user };
  }
};
