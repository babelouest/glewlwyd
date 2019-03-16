import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

import Confirm from '../Modal/Confirm';
import Edit from '../Modal/Edit';

import Navbar from './Navbar';
import Users from './Users';
import Clients from './Clients';
import Scopes from './Scopes';
import UsersMod from './UsersMod';
import ClientsMod from './ClientsMod';
import AuthScheme from './AuthScheme';
import Plugins from './Plugins';
import ScopeEdit from './ScopeEdit';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "users",
      loggedIn: false,
      users: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curUser: false,
      clients: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curClient: false,
      scopes: {list: [], offset: 0, limit: 20, searchPattern: "", pattern: false},
      curScope: false,
      confirmModal: {title: "", message: ""},
      editModal: {title: "", pattern: [], data: {}, callback: false, validateCallback: false, add: false},
      scopeModal: {title: "", data: {name: "", display_name: "", description: "", password_required: true, scheme: {}}, callback: false, add: false},
      modUsers: [],
      modClients: [],
      modSchemes: [],
      modPlugins: []
    }

    messageDispatcher.subscribe('App', (message) => {
      if (message.type === 'nav') {
        this.setState({curNav: message.message});
      } else if (message.type === 'loggedIn') {
        this.setState({loggedIn: message.message}, () => {
          if (!this.state.loggedIn) {
            this.fetchApi();
          }
        });
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
        }
      } else if (message.type === 'edit') {
        if (message.role === 'user') {
          var editModal = {
            title: i18next.t("admin.edit-user-title", {user: message.user.name}),
            pattern: this.state.config.pattern.user,
            data: message.user,
            callback: this.confirmEditUser,
            validateCallback: this.validateUser
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var editModal = {
            title: i18next.t("admin.edit-client-title", {client: message.client.name}),
            pattern: this.state.config.pattern.client,
            data: message.client,
            callback: this.confirmEditClient,
            validateCallback: this.validateClient
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
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
        }
      } else if (message.type === 'add') {
        if (message.role === 'user') {
          var editModal = {
            title: i18next.t("admin.add-user-title"),
            pattern: this.state.config.pattern.user,
            data: {},
            callback: this.confirmAddUser,
            validateCallback: this.validateUser,
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var editModal = {
            title: i18next.t("admin.add-client-title"),
            pattern: this.state.config.pattern.client,
            data: {},
            callback: this.confirmAddClient,
            validateCallback: this.validateClient,
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var scopeModal = {
            title: i18next.t("admin.add-scope-title"),
            data: {name: "", display_name: "", description: "", password_required: true, scheme: {}},
            callback: this.confirmAddScope,
            add: true
          }
          this.setState({scopeModal: scopeModal}, () => {
            $("#editScopeModal").modal({keyboard: false, show: true});
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
      }
    });
    
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
    this.confirmDeleteScope = this.confirmDeleteScope.bind(this);
    this.confirmEditScope = this.confirmEditScope.bind(this);
    this.confirmAddScope = this.confirmAddScope.bind(this);
    
    this.fetchUserMods = this.fetchUserMods.bind(this);
    this.fetchClientMods = this.fetchClientMods.bind(this);
    this.fetchAuthSchemes = this.fetchAuthSchemes.bind(this);
    this.fetchPlugins = this.fetchPlugins.bind(this);
    
    this.fetchApi();
  }
  
  fetchApi() {
    apiManager.glewlwydRequest("/profile")
    .then((res) => {
      if (res[0] && res[0].scope.indexOf(this.state.config.admin_scope) < 0) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.requires-admin-profile")});
      } else {
        this.setState({loggedIn: true}, () => {
          this.fetchUsers()
          .always(() => {
            this.fetchClients()
            .always(() => {
              this.fetchScopes();
            });
            this.fetchUserMods();
            this.fetchClientMods();
            this.fetchAuthSchemes();
            this.fetchPlugins();
          });
        });
      }
    })
    .fail((error) => {
      if (error.status !== 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
      }
    });
  }

  fetchUsers() {
    return apiManager.glewlwydRequest("/user?offset=" + this.state.users.offset + "&limit=" + this.state.users.limit + (this.state.users.searchPattern?"&pattern="+this.state.users.searchPattern:""))
    .then((users) => {
      var curUsers = this.state.users;
      curUsers.list = users;
      curUsers.pattern = this.state.config.pattern.user;
      this.setState({users: curUsers});
    });
  }

  fetchClients() {
    return apiManager.glewlwydRequest("/client?offset=" + this.state.clients.offset + "&limit=" + this.state.clients.limit + (this.state.clients.searchPattern?"&pattern="+this.state.clients.searchPattern:""))
    .then((clients) => {
      var curClients = this.state.clients;
      curClients.list = clients;
      curClients.pattern = this.state.config.pattern.client;
      this.setState({clients: curClients});
    });
  }

  fetchScopes() {
    return apiManager.glewlwydRequest("/scope?offset=" + this.state.scopes.offset + "&limit=" + this.state.scopes.limit + (this.state.scopes.searchPattern?"&pattern="+this.state.scopes.searchPattern:""))
    .then((scopes) => {
      var curScopes = this.state.scopes;
      var scopeList = [];
      var users = this.state.users;
      var clients = this.state.clients;
      curScopes.list = scopes;
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
      this.setState({scopes: curScopes, users: users, clients: clients});
    });
  }

  fetchUserMods () {
    return apiManager.glewlwydRequest("/mod/user")
    .then((modUsers) => {
      this.setState({modUsers: modUsers});
    });
  }
  
  fetchClientMods () {
    return apiManager.glewlwydRequest("/mod/client")
    .then((modClients) => {
      this.setState({modClients: modClients});
    });
  }
  
  fetchAuthSchemes () {
    return apiManager.glewlwydRequest("/mod/scheme")
    .then((modSchemes) => {
      this.setState({modSchemes: modSchemes});
    });
  }
  
  fetchPlugins () {
    return apiManager.glewlwydRequest("/mod/plugin")
    .then((modPlugins) => {
      this.setState({modPlugins: modPlugins});
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
          this.setState({editModal: {title: "", pattern: [], data: {}, callback: false}}, () => {
            $("#editModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], data: {}, callback: false}}, () => {
        $("#editModal").modal("hide");
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
          this.setState({editModal: {title: "", pattern: [], data: {}, callback: false}}, () => {
            $("#editModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], data: {}, callback: false}}, () => {
        $("#editModal").modal("hide");
      });
    }
  }

  confirmEditScope(result, scope) {
  }

  confirmAddUser(result, user) {
    if (result) {
      apiManager.glewlwydRequest("/user/", "POST", user)
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-user")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-user")});
      })
      .always(() => {
        this.fetchUsers()
        .always(() => {
          this.setState({editModal: {title: "", pattern: [], data: {}, callback: false, add: false}}, () => {
            $("#editModal").modal("hide");
          });
        });
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], data: {}, callback: false, add: false}}, () => {
        $("#editModal").modal("hide");
      });
    }
  }

  confirmAddClient(result, client) {
    if (result) {
      apiManager.glewlwydRequest("/client/" + encodeURI(client.client_id))
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-already-exists")});
      })
      .fail((error) => {
        if (error.status === 404) {
          apiManager.glewlwydRequest("/client/", "POST", client)
          .then(() => {
            messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-client")});
          })
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-client")});
          })
          .always(() => {
            this.fetchClients()
            .always(() => {
              this.setState({editModal: {title: "", pattern: [], data: {}, callback: false, add: false}}, () => {
                $("#editModal").modal("hide");
              });
            });
          });
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-client")});
        }
      });
    } else {
      this.setState({editModal: {title: "", pattern: [], data: {}, callback: false, add: false}}, () => {
        $("#editModal").modal("hide");
      });
    }
  }

  confirmAddScope(result, scope) {
  }

  validateUser(user, confirmData, add, cb) {
    var result = true, data = {};
    if (add) {
      if (user.password || confirmData.password) {
        if (user.password !== confirmData.password) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-match");
        } else if (user.password.length < 8) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid");
        }
      } else if (!user.password) {
        result = false;
        data["password"] = i18next.t("admin.user-password-mandatory");
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
        } else if (user.password.length < 8) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid");
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
        } else if (client.password.length < 8) {
          result = false;
          data["password"] = i18next.t("admin.user-password-error-invalid");
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

	render() {
		return (
      <div>
        <Notification/>
        <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
          <div className="card-header">
            <Navbar active={this.state.curNav} config={this.state.config} loggedIn={this.state.loggedIn}/>
          </div>
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
                  <UsersMod />
                </div>
                <div className={"carousel-item" + (this.state.curNav==="clients-mod"?" active":"")}>
                  <ClientsMod />
                </div>
                <div className={"carousel-item" + (this.state.curNav==="auth-schemes"?" active":"")}>
                  <AuthScheme />
                </div>
                <div className={"carousel-item" + (this.state.curNav==="plugins"?" active":"")}>
                  <Plugins />
                </div>
              </div>
            </div>
          </div>
        </div>
        <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
        <Edit title={this.state.editModal.title} pattern={this.state.editModal.pattern} data={this.state.editModal.data} callback={this.state.editModal.callback} validateCallback={this.state.editModal.validateCallback} add={this.state.editModal.add} />
        <ScopeEdit scope={this.state.scopeModal.data} add={this.state.scopeModal.add} modSchemes={this.state.modSchemes} callback={this.state.scopeModal.callback} />
      </div>
		);
	}
}

export default App;
