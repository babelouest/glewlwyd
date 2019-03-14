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
import AuthSchemes from './AuthSchemes';
import Plugins from './Plugins';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "users",
      loggedIn: false,
      users: {list: [], offset: 0, limit: 20, pattern: false},
      curUser: false,
      clients: {list: [], offset: 0, limit: 20, pattern: false},
      curClient: false,
      scopes: {list: [], offset: 0, limit: 20, pattern: false},
      curScope: false,
      confirmModal: {title: "", message: ""},
      editModal: {title: "", pattern: [], data: {}, callback: false, add: false}
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
            callback: this.confirmEditUser
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'client') {
          var editModal = {
            title: i18next.t("admin.edit-client-title", {client: message.client.name}),
            pattern: this.state.config.pattern.client,
            data: message.client,
            callback: this.confirmEditClient
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var editModal = {
            title: i18next.t("admin.edit-scope-title", {scope: message.scope.scope}),
            pattern: this.state.config.pattern.scope,
            data: message.scope,
            callback: this.confirmEditScope
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'add') {
        if (message.role === 'user') {
          var editModal = {
            title: i18next.t("admin.add-user-title"),
            pattern: this.state.config.pattern.user,
            data: {},
            callback: this.confirmAddUser,
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
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        } else if (message.role === 'scope') {
          var editModal = {
            title: i18next.t("admin.add-scope-title"),
            pattern: this.state.config.pattern.scope,
            data: {},
            callback: this.confirmAddScope,
            add: true
          }
          this.setState({editModal: editModal}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'search') {
        if (message.role === 'user') {
          var users = this.state.users;
          users.pattern = message.pattern;
          users.offset = message.offset;
          users.limit = message.limit;
          this.setState({users: users}, () => {
            this.fetchUsers();
          });
        } else if (message.role === 'client') {
          var clients = this.state.clients;
          clients.pattern = message.pattern;
          clients.offset = message.offset;
          clients.limit = message.limit;
          this.setState({clients: clients}, () => {
            this.fetchClients();
          });
        } else if (message.role === 'scope') {
          var scopes = this.state.scopes;
          scopes.pattern = message.pattern;
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

    this.fetchClients = this.fetchClients.bind(this);
    this.confirmDeleteClient = this.confirmDeleteClient.bind(this);
    this.confirmEditClient = this.confirmEditClient.bind(this);
    this.confirmAddClient = this.confirmAddClient.bind(this);

    this.fetchScopes = this.fetchScopes.bind(this);
    this.confirmDeleteScope = this.confirmDeleteScope.bind(this);
    this.confirmEditScope = this.confirmEditScope.bind(this);
    this.confirmAddScope = this.confirmAddScope.bind(this);
    
    this.fetchApi();
  }
  
  fetchApi() {
    apiManager.glewlwydRequest("/profile")
    .then((res) => {
      if (res[0] && res[0].scope.indexOf(this.state.config.admin_scope) < 0) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.requires-admin-profile")});
      } else {
        this.setState({loggedIn: true}, () => {
          this.fetchUsers();
          this.fetchClients();
          this.fetchScopes();
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
    return apiManager.glewlwydRequest("/user?offset=" + this.state.users.offset + "&limit=" + this.state.users.limit + (this.state.users.pattern?"&pattern="+this.state.users.pattern:""))
    .then((users) => {
      var curUsers = this.state.users;
      curUsers.list = users;
      this.setState({users: curUsers});
    });
  }

  fetchClients() {
    return apiManager.glewlwydRequest("/client?offset=" + this.state.clients.offset + "&limit=" + this.state.clients.limit + (this.state.clients.pattern?"&pattern="+this.state.clients.pattern:""))
    .then((clients) => {
      var curClients = this.state.clients;
      curClients.list = clients;
      this.setState({clients: curClients});
    });
  }

  fetchScopes() {
    return apiManager.glewlwydRequest("/scope?offset=" + this.state.scopes.offset + "&limit=" + this.state.scopes.limit + (this.state.scopes.pattern?"&pattern="+this.state.scopes.pattern:""))
    .then((scopes) => {
      var curScopes = this.state.scopes;
      curScopes.list = scopes;
      this.setState({scopes: curScopes});
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
      .done(() => {
        this.fetchUsers()
        .done(() => {
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
      .done(() => {
        this.fetchUsers()
        .done(() => {
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
      .done(() => {
        this.fetchUsers()
        .done(() => {
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
      .done(() => {
        this.fetchUsers()
        .done(() => {
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
      apiManager.glewlwydRequest("/user/" + encodeURI(user.username))
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-already-exists")});
      })
      .fail((error) => {
        if (error.status === 404) {
          apiManager.glewlwydRequest("/user/", "POST", user)
          .then(() => {
            messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-add-user")});
          })
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-user")});
          })
          .done(() => {
            this.fetchUsers()
            .done(() => {
              this.setState({editModal: {title: "", pattern: [], data: {}, callback: false, add: false}}, () => {
                $("#editModal").modal("hide");
              });
            });
          });
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-add-user")});
        }
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
          .done(() => {
            this.fetchUsers()
            .done(() => {
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
                  <AuthSchemes />
                </div>
                <div className={"carousel-item" + (this.state.curNav==="plugins"?" active":"")}>
                  <Plugins />
                </div>
              </div>
            </div>
          </div>
        </div>
        <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
        <Edit title={this.state.editModal.title} pattern={this.state.editModal.pattern} data={this.state.editModal.data} callback={this.state.editModal.callback} add={this.state.editModal.add} />
      </div>
		);
	}
}

export default App;
