const layers = {
  board: {
    /** all board are public by default */
    _default: { anyoneCan: "read", ownerCan: "audit" },
    _public: { anyoneCan: "create", ownerCan: "audit" },
    _private: { anyoneCan: "none" },
    _store: { anyoneCan: "read", noOneCan: "create" },

    user: {
      _default: { anyoneCan: "read", superAdminCan: "update" },
      _public: { anyoneCan: "none" },
      _private: { inherit: true },
      _store: { inherit: true },
    },
    school: {
      _default: { adminCan: "read", superAdminCan: "update" },
      _public: { anyoneCan: "none" },
      _private: { inherit: true },
      _store: { inherit: true },
      classRoom: {
        _default: { adminCan: "update", superAdminCan: "read" },
        _public: { inherit: true },
        _private: { inherit: true },
        _store: { inherit: true },
        student: {
          _default: { adminCan: "update", superAdminCan: "none" },
          _public: { inherit: true },
          _private: { inherit: true },
          _store: { inherit: true },
        },
      },
    },
  },
};

const actions = {
  blocked: -1,
  none: 1,
  read: 2,
  create: 3,
  audit: 4,
  config: 5,
  delete: 6,
  update: 7,
};

module.exports = {
  layers,
  actions,
};
