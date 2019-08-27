import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

import Confirm from '../Modal/Confirm';
import EditRecord from '../Modal/EditRecord';

import Navbar from './Navbar';
import Users from './Users';
import Clients from './Clients';
import Scopes from './Scopes';
import UserMod from './UserMod';
import ClientMod from './ClientMod';
import SchemeMod from './SchemeMod';
import Plugin from './Plugin';
import ScopeEdit from './ScopeEdit';
import ModEdit from './ModEdit';
import PluginEdit from './PluginEdit';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      lang: i18next.language,
      config: props.config,
      passwordMinLength: props.config.PasswordMinLength||8,
      curNav: "users",
      loggedIn: false,
      users: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curUser: false,
      clients: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curClient: false,
      scopes: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curScope: false,
      confirmModal: {title: "", message: ""},
      editModal: {title: "", pattern: [], source: [], data: {}, callback: false, validateCallback: false, add: false},
      scopeModal: {title: "", data: {name: "", display_name: "", description: "", password_required: true, scheme: {}}, callback: false, add: false},
      curMod: false,
      modUsers: [],
      ModModal: {title: "", role: false, data: {}, types: [], add: false, callback: false},
      modClients: [],
      modSchemes: [],
      plugins: [],
      PluginModal: {title: "", data: {}, types: [], add: false, callback: false},
      modTypes: {user: [], client: [], scheme: [], plugin: []},
      profileList: false,
      invalidCredentialMessage: false
    }
    
    this.fetchApi = this.fetchApi.bind(this);

    this.fetchUsers = this.fetchUsers.bind(this);
    this.confirmDeleteUser = this.confirmDeleteUser.bind(this);
    this.confirmEditUser = this.confirmEditUser.bind(this);
    this.confirmAddUser = this.confirmAddUser.bind(this);
    this.validateUser = this.validateUser.bind(this);

    this.fetchClients = this.fetchClients.bind(this);
    this.confirmDeleteClient = this.confirmDeleteClient.bind(this);
    this.confirmEditClient = this.confirmEditClient.bind(this);
    this.confirmAddClient = this.confirmAddClient.bind(this);
    this.validateClient = this.validateClient.bind(this);

    this.fetchScopes = this.fetchScopes.bind(this);
    this.fetchAllScopes = this.fetchAllScopes.bind(this);
    this.confirmDeleteScope = this.confirmDeleteScope.bind(this);
    this.confirmEditScope = this.confirmEditScope.bind(this);
    this.confirmAddScope = this.confirmAddScope.bind(this);
    
    this.fetchModTypes = this.fetchModTypes.bind(this);
    this.fetchUserMods = this.fetchUserMods.bind(this);
    this.fetchClientMods = this.fetchClientMods.bind(this);
    this.fetchSchemeMods = this.fetchSchemeMods.bind(this);
    this.fetchPlugins = this.fetchPlugins.bind(this);
    
    this.confirmAddUserMod = this.confirmAddUserMod.bind(this);
    this.confirmEditUserMod = this.confirmEditUserMod.bind(this);
    this.confirmDeleteUserMod = this.confirmDeleteUserMod.bind(this);
    
    this.confirmAddClientMod = this.confirmAddClientMod.bind(this);
    this.confirmEditClientMod = this.confirmEditClientMod.bind(this);
    this.confirmDeleteClientMod = this.confirmDeleteClientMod.bind(this);
    
    this.confirmAddSchemeMod = this.confirmAddSchemeMod.bind(this);
    this.confirmEditSchemeMod = this.confirmEditSchemeMod.bind(this);
    this.confirmDeleteSchemeMod = this.confirmDeleteSchemeMod.bind(this);

    this.confirmAddPluginMod = this.confirmAddPluginMod.bind(this);
    this.confirmEditPluginMod = this.confirmEditPluginMod.bind(this);
    this.confirmDeletePluginMod = this.confirmDeletePluginMod.bind(this);

    messageDispatcher.subscribe('App', (message) => {
      if (message.type === 'nav') {
        this.setState({curNav: message.message});
      } else if (message.type === 'profile') {
        this.fetchApi();
      } else if (message.type === 'loggedIn') {
        this.setState({loggedIn: message.message}, () => {
          if (!this.state.loggedIn) {
            this.fetchApi();
          }
        });
      } else if (message.type === 'lang') {
        this.setState({lang: i18next.language});
      } else if (message.type === 'delete') {
        if (message.role === 'user') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-user-title", {user: message.user.name}),
            message: i18next.t("admin.confirm-delete-user", {username: message.user.username, name: message.user.name}),
            callback: this.confirmDeleteUser
          }
          this.setState({confirmModal: confirmModal, curUser: message.user}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-client-title", {client: message.client.name}),
            message: i18next.t("admin.confirm-delete-client", {clientId: message.client.client_id, name: message.client.name}),
            callback: this.confirmDeleteClient
          }
          this.setState({confirmModal: confirmModal, curClient: message.client}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-scope-title", {scope: message.scope.name}),
            message: i18next.t("admin.confirm-delete-scope", {username: message.scope.scope, name: message.scope.display_name}),
            callback: this.confirmDeleteScope
          }
          this.setState({confirmModal: confirmModal, curScope: message.scope}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'userMod') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-mod-title", {mod: message.mod.display_name}),
            message: i18next.t("admin.confirm-delete-mod", {mod: message.mod.display_name}),
            callback: this.confirmDeleteUserMod
          }
          this.setState({confirmModal: confirmModal, curMod: message.mod}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'clientMod') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-mod-title", {mod: message.mod.display_name}),
            message: i18next.t("admin.confirm-delete-mod", {mod: message.mod.display_name}),
            callback: this.confirmDeleteClientMod
          }
          this.setState({confirmModal: confirmModal, curMod: message.mod}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'schemeMod') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-mod-title", {mod: message.mod.display_name}),
            message: i18next.t("admin.confirm-delete-mod", {mod: message.mod.display_name}),
            callback: this.confirmDeleteSchemeMod
          }
          this.setState({confirmModal: confirmModal, curMod: message.mod}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'plugin') {
          var confirmModal = {
            title: i18next.t("admin.confirm-delete-mod-title", {mod: message.mod.display_name}),
            message: i18next.t("admin.confirm-delete-mod", {mod: message.mod.display_name}),
            callback: this.confirmDeletePluginMod
          }
          this.setState({confirmModal: confirmModal, curMod: message.mod}, () => {
            $("#confirmModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'edit') {
        if (message.role === 'user') {
          var editModal = {
            title: i18next.t("admin.edit-user-title", {user: message.user.name}),
            pattern: this.state.config.pattern.user,
            source: this.state.modUsers,
            data: message.user,
            callback: this.confirmEditUser,
            validateCallback: this.validateUser
          }
          this.setState({editModal: editModal}, () => {
            $("#editRecordModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var editModal = {
            title: i18next.t("admin.edit-client-title", {client: message.client.name}),
            pattern: this.state.config.pattern.client,
            data: message.client,
            source: this.state.modClients,
            callback: this.confirmEditClient,
            validateCallback: this.validateClient
          }
          this.setState({editModal: editModal}, () => {
            $("#editRecordModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var scopeModal = {
            title: i18next.t("admin.edit-scope-title", {scope: message.scope.scope}),
            data: message.scope,
            callback: this.confirmEditScope
          }
          this.setState({scopeModal: scopeModal}, () => {
            $("#editScopeModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'userMod') {
          var ModModal = {
            title: i18next.t("admin.edit-mod-title", {mod: message.mod.display_name}),
            data: message.mod,
            role: "user",
            types: this.state.modTypes.user,
            callback: this.confirmEditUserMod
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'clientMod') {
          var ModModal = {
            title: i18next.t("admin.edit-mod-title", {mod: message.mod.display_name}),
            data: message.mod,
            types: this.state.modTypes.client,
            role: "client",
            callback: this.confirmEditClientMod
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'schemeMod') {
          var ModModal = {
            title: i18next.t("admin.edit-mod-title", {mod: message.mod.display_name}),
            data: message.mod,
            types: this.state.modTypes.scheme,
            role: "scheme",
            callback: this.confirmEditSchemeMod
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'plugin') {
          var PluginModal = {
            title: i18next.t("admin.edit-mod-title", {mod: message.mod.display_name}),
            data: message.mod,
            types: this.state.modTypes.plugin,
            callback: this.confirmEditPluginMod
          }
          this.setState({PluginModal: PluginModal}, () => {
            $("#editPluginModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'add') {
        if (message.role === 'user') {
          var editModal = {
            title: i18next.t("admin.add-user-title"),
            pattern: this.state.config.pattern.user,
            source: this.state.modUsers,
            data: {username: "", name: "", password: "", email: "", enabled: true, scope: []},
            callback: this.confirmAddUser,
            validateCallback: this.validateUser,
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editRecordModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var editModal = {
            title: i18next.t("admin.add-client-title"),
            pattern: this.state.config.pattern.client,
            source: this.state.modClients,
            data: {client_id: "", confidential: false, client_secret: "", enabled: true, name: "", password: "", redirect_uri: [], scope: []},
            callback: this.confirmAddClient,
            validateCallback: this.validateClient,
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editRecordModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var scopeModal = {
            title: i18next.t("admin.add-scope-title"),
            data: {name: "", display_name: "", description: "", password_required: true, password_max_age: 0, scheme: {}},
            callback: this.confirmAddScope,
            add: true
          }
          this.setState({scopeModal: scopeModal}, () => {
            $("#editScopeModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'userMod') {
          var ModModal = {
            title: i18next.t("admin.add-mod-title"),
            data: {order_rank: this.state.modUsers.length, parameters: {}},
            types: this.state.modTypes.user,
            role: "user",
            callback: this.confirmAddUserMod,
            add: true
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'clientMod') {
          var ModModal = {
            title: i18next.t("admin.add-mod-title"),
            data: {order_rank: this.state.modClients.length, parameters: {}},
            types: this.state.modTypes.client,
            role: "client",
            callback: this.confirmAddClientMod,
            add: true
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'schemeMod') {
          var ModModal = {
            title: i18next.t("admin.add-mod-title"),
            data: {parameters: {}},
            types: this.state.modTypes.scheme,
            role: "scheme",
            callback: this.confirmAddSchemeMod,
            add: true
          }
          this.setState({ModModal: ModModal}, () => {
            $("#editModModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'plugin') {
          var PluginModal = {
            title: i18next.t("admin.add-mod-title"),
            data: {parameters: {}},
            types: this.state.modTypes.plugin,
            callback: this.confirmAddPluginMod,
            add: true
          }
          this.setState({PluginModal: PluginModal}, () => {
            $("#editPluginModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'swap') {
        if (message.role === 'userMod') {
          apiManager.glewlwydRequest("/mod/user/" + encodeURI(message.mod.name), "PUT", message.mod)
          .then(() => {
            return apiManager.glewlwydRequest("/mod/user/" + encodeURI(message.previousMod.name), "PUT", message.previousMod)
            .fail(() => {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
            })
          })
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
          })
          .always(() => {
            this.fetchUserMods()
            this.fetchUsers();
          });
        } else if (message.role === 'clientMod') {
          apiManager.glewlwydRequest("/mod/client/" + encodeURI(message.mod.name), "PUT", message.mod)
          .then(() => {
            return apiManager.glewlwydRequest("/mod/client/" + encodeURI(message.previousMod.name), "PUT", message.previousMod)
            .fail(() => {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
            })
          })
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
          })
          .always(() => {
            this.fetchClientMods()
            this.fetchClients();
          });
        }
      } else if (message.type === 'search') {
        if (message.role === 'user') {
          var users = this.state.users;
          users.searchPattern = message.searchPattern;
          users.offset = message.offset;
          users.limit = message.limit;
          this.setState({users: users}, () => {
            this.fetchUsers();
          });
        } else if (message.role === 'client') {
          var clients = this.state.clients;
          clients.searchPattern = message.searchPattern;
          clients.offset = message.offset;
          clients.limit = message.limit;
          this.setState({clients: clients}, () => {
            this.fetchClients();
          });
        } else if (message.role === 'scope') {
          var scopes = this.state.scopes;
          scopes.searchPattern = message.searchPattern;
          scopes.offset = message.offset;
          scopes.limit = message.limit;
          this.setState({scopes: scopes}, () => {
            this.fetchScopes();
          });
        }
      } else if (message.type === 'refresh') {
        if (message.role === 'schemeMod') {
          this.fetchSchemeMods();
        } else if (message.role === 'userMod') {
          this.fetchUserMods();
        } else if (message.role === 'clientMod') {
          this.fetchClientMods();
        } else if (message.role === 'pluginMod') {
          this.fetchPlugins();
        }
      }
    });
    
    if (this.state.config) {
      this.fetchApi();
    }
  }
  
  fetchApi() {
    apiManager.glewlwydRequest("/profile_list")
    .then((res) => {
      this.setState({profileList: res}, () => {
        this.fetchUsers()
        .then(() => {
          this.setState({invalidCredentialMessage: false}, () => {
            this.fetchClients()
            .always(() => {
              this.fetchScopes();
            });
            this.fetchModTypes();
            this.fetchUserMods();
            this.fetchClientMods();
            this.fetchSchemeMods();
            this.fetchPlugins();
            this.fetchAllScopes();
          });
        })
        .fail((error) => {
          this.setState({invalidCredentialMessage: true});
        });
      });
    })
    .fail((error) => {
      this.setState({invalidCredentialMessage: true}, () => {
        if (error.status === 401) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.requires-admin-scope")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    });
  }

  fetchUsers() {
    return apiManager.glewlwydRequest("/user?offset=" + this.state.users.offset + "&limit=" + this.state.users.limit + (this.state.users.searchPattern?"&pattern="+this.state.users.searchPattern:""))
    .then((users) => {
      var curUsers = this.state.users;
      curUsers.list = users;
      curUsers.pattern = this.state.config.pattern.user;
      this.setState({users: curUsers, loggedIn: true});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.requires-admin-scope")});
        this.setState({loggedIn: false});
      }
    });
  }

  fetchClients() {
    return apiManager.glewlwydRequest("/client?offset=" + this.state.clients.offset + "&limit=" + this.state.clients.limit + (this.state.clients.searchPattern?"&pattern="+this.state.clients.searchPattern:""))
    .then((clients) => {
      var curClients = this.state.clients;
      curClients.list = clients;
      curClients.pattern = this.state.config.pattern.client;
      this.setState({clients: curClients});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }

  fetchScopes() {
    return apiManager.glewlwydRequest("/scope?offset=" + this.state.scopes.offset + "&limit=" + this.state.scopes.limit + (this.state.scopes.searchPattern?"&pattern="+this.state.scopes.searchPattern:""))
    .then((scopes) => {
      var curScopes = this.state.scopes;
      curScopes.list = scopes;
      this.setState({scopes: curScopes});
    })
    .fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  fetchAllScopes() {
    return apiManager.glewlwydRequest("/scope?limit=0")
    .then((scopes) => {
      var scopeList = [];
      var users = this.state.users;
      var clients = this.state.clients;
      var config = this.state.config;
      scopes.forEach((scope) => {
        scopeList.push(scope.name);
      });
      users.pattern.forEach((pat) => {
        if (pat.name === "scope") {
          pat.listElements = scopeList;
        }
      });
      clients.pattern.forEach((pat) => {
        if (pat.name === "scope") {
          pat.listElements = scopeList;
        }
      });
      config.scopes = scopes;
      this.setState({users: users, clients: clients, config: config});
    });
  }

  fetchUserMods () {
    return apiManager.glewlwydRequest("/mod/user")
    .then((modUsers) => {
      this.setState({modUsers: modUsers});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  fetchModTypes () {
    return apiManager.glewlwydRequest("/mod/type")
    .then((modTypes) => {
      this.setState({modTypes: modTypes});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  fetchClientMods () {
    return apiManager.glewlwydRequest("/mod/client")
    .then((modClients) => {
      this.setState({modClients: modClients});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  fetchSchemeMods () {
    return apiManager.glewlwydRequest("/mod/scheme")
    .then((modSchemes) => {
      this.setState({modSchemes: modSchemes});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  fetchPlugins () {
    return apiManager.glewlwydRequest("/mod/plugin")
    .then((plugins) => {
      this.setState({plugins: plugins});
    }).fail((err) => {
      if (err.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-fetch")});
      } else {
        this.setState({loggedIn: false});
      }
    });
  }
  
  confirmDeleteUser(result) {
    if (result) {
      apiManager.glewlwydRequest("/user/" + encodeURI(this.state.curUser.username), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-user")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-user")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmDeleteClient(result) {
    if (result) {
      apiManager.glewlwydRequest("/client/" + encodeURI(this.state.curClient.client_id), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-client")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-client")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmDeleteScope(result) {
    if (result) {
      apiManager.glewlwydRequest("/scope/" + encodeURI(this.state.curScope.name), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-scope")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-scope")});
      })
      .always(() => {
        this.fetchScopes()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmEditUser(result, user) {
    if (result) {
      apiManager.glewlwydRequest("/user/" + encodeURI(user.username), "PUT", user)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-set-user")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-set-user")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false}}, () => {
            $("#editRecordModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false}}, () => {
        $("#editRecordModal").modal("hide");
      });
    }
  }

  confirmEditClient(result, client) {
    if (result) {
      apiManager.glewlwydRequest("/client/" + encodeURI(client.client_id), "PUT", client)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-set-client")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-set-client")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false}}, () => {
            $("#editRecordModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false}}, () => {
        $("#editRecordModal").modal("hide");
      });
    }
  }

  confirmEditScope(result, scope) {
    if (result) {
      apiManager.glewlwydRequest("/scope/" + encodeURI(scope.name), "PUT", scope)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-set-scope")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-set-scope")});
      })
      .always(() => {
        this.fetchScopes()
        .always(() => {
          this.setState({scopeModal: {data: {}, callback: false}}, () => {
            $("#editScopeModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({scopeModal: {data: {}, callback: false}}, () => {
        $("#editScopeModal").modal("hide");
      });
    }
  }

  confirmAddUser(result, user) {
    if (result) {
      var source = (user.source?"?source="+user.source:"");
      apiManager.glewlwydRequest("/user/" + source, "POST", user)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-user")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-user")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false, add: false}}, () => {
            $("#editRecordModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false, add: false}}, () => {
        $("#editRecordModal").modal("hide");
      });
    }
  }

  confirmAddClient(result, client) {
    if (result) {
      var source = (client.source?"?source="+client.source:"");
      apiManager.glewlwydRequest("/client/" + source, "POST", client)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-client")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-client")});
      })
      .always(() => {
        this.fetchClients()
        .always(() => {
          this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false, add: false}}, () => {
            $("#editRecordModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], source: [], data: {}, callback: false, add: false}}, () => {
        $("#editRecordModal").modal("hide");
      });
    }
  }

  confirmAddScope(result, scope) {
    if (result) {
      apiManager.glewlwydRequest("/scope/", "POST", scope)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-scope")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-scope")});
      })
      .always(() => {
        this.fetchScopes()
        .always(() => {
          this.setState({scopeModal: {data: {}, callback: false}}, () => {
            $("#editScopeModal").modal("hide");
          });
        });
      });
    } else {
      $("#editScopeModal").modal("hide");
    }
  }

  validateUser(user, confirmData, add, cb) {
    var result = true, data = {};
    if (add) {
      if (user.password != undefined || confirmData.password != undefined) {
        if (user.password !== confirmData.password) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-match");
        } else if (user.password.length && user.password.length < this.state.passwordMinLength) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid", {minLength: this.state.passwordMinLength});
        }
      }
      if (!user.username) {
        result = false;
        data["username"] = i18next.t("admin.user-username-mandatory");
        cb(result, data);
      } else {
        apiManager.glewlwydRequest("/user/" + encodeURI(user.username))
        .then(() => {
          result = false;
          data["username"] = i18next.t("admin.user-username-exists");
        })
        .always(() => {
          cb(result, data);
        });
      }
    } else {
      if (user.password || confirmData.password) {
        if (user.password !== confirmData.password) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-match");
        } else if (user.password.length && user.password.length < this.state.passwordMinLength) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid", {minLength: this.state.passwordMinLength});
        }
      }
      cb(result, data);
    }
  }

  validateClient(client, confirmData, add, cb) {
    var result = true, data = {};
    if (client.confidential) {
      if (client.password || confirmData.password) {
        if (client.password !== confirmData.password) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-match");
        } else if (client.password.length && client.password.length < this.state.passwordMinLength) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid", {minLength: this.state.passwordMinLength});
        }
      } else if (!client.password && add) {
        result = false;
        data["password"] = i18next.t("admin.user-password-mandatory");
      }
    }
    if (add) {
      if (!client.client_id) {
        result = false;
        data["client_id"] = i18next.t("admin.client-client-id-mandatory");
        cb(result, data);
      } else {
        apiManager.glewlwydRequest("/client/" + encodeURI(client.client_id))
        .then(() => {
          result = false;
          data["client_id"] = i18next.t("admin.client-client-id-exists");
        })
        .always(() => {
          cb(result, data);
        });
      }
    } else {
      cb(result, data);
    }
  }
  
  confirmAddUserMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/user/", "POST", mod)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-mod")});
      })
      .fail((err) => {
        if (err.status === 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
        }
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-mod")});
      })
      .always(() => {
        this.fetchUserMods()
        .always(() => {
          this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
            $("#editModModal").modal("hide");
            this.fetchUsers();
          });
        });
      });
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmEditUserMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/user/" + encodeURI(mod.name), "PUT", mod)
      .then(() => {
        apiManager.glewlwydRequest("/mod/user/" + encodeURI(mod.name) + "/reset/", "PUT")
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-edit-mod")});
        })
        .fail((err) => {
          if (err.status === 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
          }
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
        })
        .always(() => {
          this.fetchUserMods()
          .always(() => {
            this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
              $("#editModModal").modal("hide");
              this.fetchUsers();
            });
          });
        });
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
      })
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmDeleteUserMod(result) {
    if (result) {
      apiManager.glewlwydRequest("/mod/user/" + encodeURI(this.state.curMod.name), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-mod")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-mod")});
      })
      .always(() => {
        this.fetchUserMods()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
            this.fetchUsers();
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmAddClientMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/client/", "POST", mod)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-mod")});
      })
      .fail((err) => {
        if (err.status === 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
        }
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-mod")});
      })
      .always(() => {
        this.fetchClientMods()
        .always(() => {
          this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
            $("#editModModal").modal("hide");
            this.fetchClients();
          });
        });
      });
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmEditClientMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/client/" + encodeURI(mod.name), "PUT", mod)
      .then(() => {
        apiManager.glewlwydRequest("/mod/client/" + encodeURI(mod.name) + "/reset/", "PUT")
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-edit-mod")});
        })
        .fail((err) => {
          if (err.status === 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
          }
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
        })
        .always(() => {
          this.fetchClientMods()
          .always(() => {
            this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
              $("#editModModal").modal("hide");
              this.fetchClients();
            });
          });
        });
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
      })
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmDeleteClientMod(result) {
    if (result) {
      apiManager.glewlwydRequest("/mod/client/" + encodeURI(this.state.curMod.name), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-mod")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-mod")});
      })
      .always(() => {
        this.fetchClientMods()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
            this.fetchClients();
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmAddSchemeMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/scheme/", "POST", mod)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-mod")});
      })
      .fail((err) => {
        if (err.status === 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
        }
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-mod")});
      })
      .always(() => {
        this.fetchSchemeMods()
        .always(() => {
          this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
            $("#editModModal").modal("hide");
          });
        });
      });
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmEditSchemeMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/scheme/" + encodeURI(mod.name), "PUT", mod)
      .then(() => {
          apiManager.glewlwydRequest("/mod/scheme/" + encodeURI(mod.name) + "/reset/", "PUT")
          .then(() => {
            messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-edit-mod")});
          })
          .fail((err) => {
            if (err.status === 400) {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
            }
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
          })
          .always(() => {
            this.fetchSchemeMods()
          });
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
      })
      .always(() => {
        this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
          $("#editModModal").modal("hide");
        });
      });
    } else {
      $("#editModModal").modal("hide");
    }
  }

  confirmDeleteSchemeMod(result) {
    if (result) {
      apiManager.glewlwydRequest("/mod/scheme/" + encodeURI(this.state.curMod.name), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-mod")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-mod")});
      })
      .always(() => {
        this.fetchSchemeMods()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

  confirmAddPluginMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/plugin/", "POST", mod)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-mod")});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-mod")});
        if (err.status === 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
        }
      })
      .always(() => {
        this.fetchPlugins()
        .always(() => {
          this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
            $("#editPluginModal").modal("hide");
          });
        });
      });
    } else {
      $("#editPluginModal").modal("hide");
    }
  }

  confirmEditPluginMod(result, mod) {
    if (result) {
      apiManager.glewlwydRequest("/mod/plugin/" + encodeURI(mod.name), "PUT", mod)
      .then(() => {
        apiManager.glewlwydRequest("/mod/plugin/" + encodeURI(mod.name) + "/reset/", "PUT")
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-edit-mod")});
        })
        .fail((err) => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
          if (err.status === 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
          }
        })
        .always(() => {
          this.fetchPlugins()
          .always(() => {
            this.setState({ModModal: {data: {}, callback: false, types: []}}, () => {
              $("#editPluginModal").modal("hide");
            });
          });
        })
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
      })
    } else {
      $("#editPluginModal").modal("hide");
    }
  }

  confirmDeletePluginMod(result) {
    if (result) {
      apiManager.glewlwydRequest("/mod/plugin/" + encodeURI(this.state.curMod.name), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-mod")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-mod")});
      })
      .always(() => {
        this.fetchPlugins()
        .always(() => {
          this.setState({confirmModal: {title: "", message: ""}}, () => {
            $("#confirmModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({confirmModal: {title: "", message: ""}}, () => {
        $("#confirmModal").modal("hide");
      });
    }
  }

	render() {
    var invalidCredentialMessage;
    if (this.state.invalidCredentialMessage) {
      invalidCredentialMessage = <div className="alert alert-danger" role="alert">{i18next.t("admin.error-credential-message")}</div>
    }
    if (this.state.config) {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <Navbar active={this.state.curNav} config={this.state.config} loggedIn={this.state.loggedIn} profileList={this.state.profileList}/>
            </div>
            {invalidCredentialMessage}
            <div className="card-body">
              <div id="carouselBody" className="carousel slide" data-ride="carousel">
                <div className="carousel-inner">
                  <div className={"carousel-item" + (this.state.curNav==="users"?" active":"")}>
                    <Users config={this.state.config} users={this.state.users} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="clients"?" active":"")}>
                    <Clients config={this.state.config} clients={this.state.clients} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="scopes"?" active":"")}>
                    <Scopes config={this.state.config} scopes={this.state.scopes} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="users-mod"?" active":"")}>
                    <UserMod mods={this.state.modUsers} types={this.state.modTypes.user} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="clients-mod"?" active":"")}>
                    <ClientMod mods={this.state.modClients} types={this.state.modTypes.client} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="auth-schemes"?" active":"")}>
                    <SchemeMod mods={this.state.modSchemes} types={this.state.modTypes.scheme} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="plugins"?" active":"")}>
                    <Plugin mods={this.state.plugins} types={this.state.modTypes.plugin}/>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <Notification/>
          <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
          <EditRecord title={this.state.editModal.title} pattern={this.state.editModal.pattern} source={this.state.editModal.source} data={this.state.editModal.data} callback={this.state.editModal.callback} validateCallback={this.state.editModal.validateCallback} add={this.state.editModal.add} />
          <ScopeEdit title={this.state.scopeModal.title} scope={this.state.scopeModal.data} add={this.state.scopeModal.add} modSchemes={this.state.modSchemes} callback={this.state.scopeModal.callback} />
          <ModEdit title={this.state.ModModal.title} role={this.state.ModModal.role} mod={this.state.ModModal.data} add={this.state.ModModal.add} types={this.state.ModModal.types} callback={this.state.ModModal.callback} config={this.state.config} />
          <PluginEdit title={this.state.PluginModal.title} mod={this.state.PluginModal.data} add={this.state.PluginModal.add} types={this.state.PluginModal.types} callback={this.state.PluginModal.callback} config={this.state.config} />
        </div>
      );
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <h4>
                <span className="badge badge-danger">
                  {i18next.t("error-api-connect")}
                </span>
              </h4>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default App;
