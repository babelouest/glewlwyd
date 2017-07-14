/**
 * 
 * Glewlwyd OAuth2 Authorization Server
 *
 * Web application for server resource management
 *
 * Copyright 2017 Nicolas Mora <mail@babelouest.org>
 * 
 * The front-end application is under MIT Licence (MIT)
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

var Button = ReactBootstrap.Button;
var Checkbox = ReactBootstrap.Checkbox;
var Modal = ReactBootstrap.Modal;

$(function() {
  
  /**
   * Web application parameters
   * Except for glewlwyd_server_url which I recommend to update, 
   * the other values are not to be modified if you didn't change
   * the default parameters values during the installation
   */
  var oauth = {
    client_id: "g_admin",                  /* client_id used for the glewlwyd manager app, default value is "g_admin", update this value if you have changed it in your installation */
    glewlwyd_server_url: "../",            /* Default value if the web app is hosted by the API server. For security, I recommend to put the absolute url, e.g. https://auth.domain.com/ */
    redirect_uri: "../app/index.html",     /* Path to Glewlwyd manager index.html page */
    access_token_cookie: "g_access_token", /* Name of the cookie to store the access_token */
    /**
     *
     * This will contain server config variables, do not modify them. 
     * Anyway, if you do modify them, they will be overwritten
     * 
     */
    access_token: false,
    admin_scope: "",
    api_prefix: ""
  };
  
  // Global lists
  var scopeList = [];
  var resourceList = [];
  var authorizationTypeList = [];
  
  // tab menu
  $('#nav li a').click(function() {
    $('#nav li').removeClass();
    $(this).parent().addClass('active');
    if (!$(this).parent().hasClass('dropdown'))
      $(".navbar-collapse").collapse('hide');
  });

  // Parse query parameters
  function getQueryParams(qs) {
    qs = qs.split('+').join(' ');

    var params = {},
      tokens,
      re = /[#&]?([^=]+)=([^&]*)/g;

    while (tokens = re.exec(qs)) {
      params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
    }

    return params;
  }
  
  var currentUser = {loggedIn: false, name: "", email: ""};

  // Function that will be used on every API call
  function APIRequest (method, url, data) {
    return $.ajax({
      method: method,
      url: oauth.glewlwyd_server_url + oauth.api_prefix + url,
      data: JSON.stringify(data),
      contentType: data?"application/json; charset=utf-8":null,
      headers: {"Authorization": "Bearer " + oauth.access_token}
    })
    .fail(function (error) {
      if (error.status === 401) {
        oauth.access_token = false;
        currentUser.loggedIn = false;
        ReactDOM.render(
          <LoginComponent user={currentUser} />,
          document.getElementById('LoginComponent')
        );
      }
    });
  }

  /**
   * get access_token from url, or from cookie
   */
  function init() {
    if (params.access_token) {
      oauth.access_token = params.access_token;
      var expires = new Date();
      expires.setTime(expires.getTime() + (params.expires_in * 1000));
      Cookies.set(oauth.access_token_cookie, params.access_token, {expires: expires});
      document.location = "#";
    } else if (params.error) {
      ReactDOM.render(
        <MessageModal show={true} title={"Error"} message={"You are not authorized to connect to this application"} />,
        document.getElementById('modal')
      );
    } else if (Cookies.get(oauth.access_token_cookie)) {
      oauth.access_token = Cookies.get(oauth.access_token_cookie);
    }
    
    /**
     * If an acces_token is present, use it to get all lists
     * if no access_token, display the login button
     */
    if (oauth.access_token) {
      APIRequest("GET", "/profile/")
      .then(function (result) {
        currentUser.loggedIn = true;
        currentUser.name = result.name;
        currentUser.email = result.email;
        loadLists();
      })
      .fail(function (error) {
        if (error.status === 401) {
          currentUser.loggedIn = false;
        }
      })
      .always(function () {
        ReactDOM.render(
          <LoginInformation user={currentUser} />,
          document.getElementById('connectMessage')
        );
        ReactDOM.render(
          <LoginComponent user={currentUser} />,
          document.getElementById('LoginComponent')
        );
        ReactDOM.render(
          <SpinnerModal show={false} />,
          document.getElementById('spinner')
        );
      });
    } else {
      ReactDOM.render(
        <ConnectMessage />,
        document.getElementById('connectMessage')
      );
      ReactDOM.render(
        <LoginComponent user={currentUser} />,
        document.getElementById('LoginComponent')
      );
      ReactDOM.render(
        <SpinnerModal show={false} />,
        document.getElementById('spinner')
      );
    }
  }

  // Load all lists at startup
  function loadLists () {
    var promises = [
      APIRequest("GET", "/user/"),
      APIRequest("GET", "/client/"),
      APIRequest("GET", "/scope/"),
      APIRequest("GET", "/resource/"),
      APIRequest("GET", "/authorization/")
    ];
    
    $.when(promises)
    .then(function (results) {
      results[0].done(function (result) {
        ReactDOM.render(
          <UserTable users={result} />,
          document.getElementById('users')
        );
      });
      
      results[1].done(function (result) {
        ReactDOM.render(
          <ClientTable clients={result} />,
          document.getElementById('clients')
        );
      });
      
      results[2].done(function (result) {
        scopeList = result;
        ReactDOM.render(
          <ScopeTable scopes={scopeList} />,
          document.getElementById('scopes')
        );
      });
      
      results[3].done(function (result) {
        resourceList = result;
        ReactDOM.render(
          <ResourceTable resources={resourceList} />,
          document.getElementById('resources')
        );
      });
      
      results[4].done(function (result) {
        authorizationTypeList = result;
        ReactDOM.render(
          <AuthorizationTypeList authTypeList={result} />,
          document.getElementById('authType')
        );
      });
    })
    .fail(function (error) {
      if (error.status === 401) {
        currentUser.loggedIn = false;
      }
    });
  }
  
  /**
   * User table management component
   */
  class UserTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        users: this.props.users, 
      };
      
      this.runSearch = this.runSearch.bind(this);
      
      this.openModalAdd = this.openModalAdd.bind(this);
      this.saveUser = this.saveUser.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.openModalDelete = this.openModalDelete.bind(this);
      this.deleteUser = this.deleteUser.bind(this);
      this.openAlertModal = this.openAlertModal.bind(this);
      this.sendEmailPassword = this.sendEmailPassword.bind(this);
    }
    
    userDetails (user) {
      ReactDOM.render(
        <UserDetails user={user} />,
        document.getElementById('userDetails')
      );
      APIRequest("GET", "/user/" + user.login + "/session/")
      .then(function (result) {
        ReactDOM.render(
          <UserSessionTable sessionList={result} login={user.login}/>,
          document.getElementById('userSessionTable')
        );
      });
      APIRequest("GET", "/user/" + user.login + "/refresh_token/")
      .then(function (result) {
        ReactDOM.render(
          <UserTokenTable tokenList={result} login={user.login}/>,
          document.getElementById('userTokenTable')
        );
      });
      $('.nav-tabs a[href="#userDetail"]').tab('show');
    }
    
    openModalAdd (event) {
      event.preventDefault();
      ReactDOM.render(
        <UserEditModal show={true} add={true} closeModal={this.saveUser} />,
        document.getElementById('modal')
      );
    }
    
    openModalEdit (user) {
      var cloneUser = $.extend({}, user);
      ReactDOM.render(
        <UserEditModal show={true} add={false} user={cloneUser} closeModal={this.saveUser} />,
        document.getElementById('modal')
      );
    }
    
    openModalDelete (user) {
      var message = "Are your sure you want to delete user '" + user.login + "'";
      ReactDOM.render(
        <ConfirmModal show={true} title={"User"} message={message} onClose={this.deleteUser} />,
        document.getElementById('modal')
      );
      this.setState({editUser: user});
    }
    
    openAlertModal (message) {
      ReactDOM.render(
        <MessageModal show={true} title={"User"} message={message} />,
        document.getElementById('modal')
      );
    }
    
    deleteUser (result) {
      if (result) {
        var self = this;
        APIRequest("DELETE", "/user/" + this.state.editUser.login)
        .then(function (result) {
            var users = self.state.users;
            for (var key in users) {
              if (users[key].login === self.state.editUser.login) {
                users.splice(key, 1);
                break;
              }
            };
            self.setState({users: users});
            self.openAlertModal("User deleted");
        })
        .fail(function (result) {
          self.openAlertModal("Error deleting user");
        });
      }
    }
    
    saveUser (add, user) {
      var self = this;
      if (!user.password) {
        delete(user.password);
      }
      if (add) {
        APIRequest("GET", "/user/" + user.login)
        .then(function (result) {
          self.openAlertModal("Error, login '" + user.login + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "/user/", user)
          .then(function (result) {
            var users = self.state.users;
            users.push(user);
            self.setState({users: users});
            self.openAlertModal("User created");
          })
          .fail(function (error) {
            self.openAlertModal("Error adding user");
          });
        })
        
      } else {
        APIRequest("PUT", "/user/" + user.login, user)
        .then(function () {
          var users = self.state.users;
          for (var key in users) {
            if (users[key].login === user.login) {
              users[key] = user;
            }
          };
          self.setState({users: users});
            self.openAlertModal("User updated");
          })
          .fail(function (error) {
            self.openAlertModal("Error updating user");
        });
      }
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "/user/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching users");
        });
      } else {
        APIRequest("GET", "/user/" + "?limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching users");
        });
      }
    }
    
    sendEmailPassword (user) {
      var self = this;
      APIRequest("POST", "/user/" + user.login + "/reset_password")
      .then(function (result) {
        self.openAlertModal("Email sent to user");
      })
      .fail(function (error) {
        self.openAlertModal("Error sending email");
      });
    }

    render() {
      var self = this;
      var rows = [];
      this.state.users.forEach(function(user, index) {
        rows.push(
          <UserRow user={user} key={index} userDetails={self.userDetails} openModalEdit={self.openModalEdit} openModalDelete={self.openModalDelete} sendEmailPassword={self.sendEmailPassword} />
        );
      });
      
      return (
        <div>
          <ListNavigation updateNavigation={this.runSearch} />
          <Button className="btn btn-default" onClick={this.openModalAdd} data-toggle="tooltip" title="Add a new user">
            <i className="fa fa-plus"></i>
          </Button>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Backend</th>
                <th>Login</th>
                <th>Name</th>
                <th>E-mail</th>
                <th>Scopes</th>
                <th>Enabled</th>
                <th></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }

  function UserRow (props) {
    return (
      <tr className={!props.user.enabled?"danger":""}>
        <td>{props.user.source}</td>
        <td>{props.user.login}</td>
        <td>{props.user.name}</td>
        <td>{props.user.email}</td>
        <td>{props.user.scope.join(", ")}</td>
        <td>{String(props.user.enabled)}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.userDetails(props.user)} data-toggle="tooltip" title="Display user details">
                <i className="fa fa-eye"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.sendEmailPassword(props.user)} data-toggle="tooltip" title="Send an email to change the password" disabled={!props.user.email}>
                <i className="fa fa-envelope"></i>
              </Button>
            </div>
          </div>
        </td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.user)} data-toggle="tooltip" title="Edit user profile">
                <i className="fa fa-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.user)} data-toggle="tooltip" title="Delete user">
                <i className="fa fa-trash"></i>
              </Button>
            </div>
          </div>
        </td>
      </tr>
    );
  }
  
  class UserEditModal extends React.Component {
    constructor(props) {
      super(props);
      var user = props.user;
      if (props.add) {
        user = {
          source: "database",
          name: "",
          login: "",
          email: "",
          enabled: true,
          scope: []
        }
      }
      user.password = "";
      user.confirmPassword = "";
      this.state = {
        show: props.show, 
        add: this.props.add, 
        user: user, 
        closeModal: this.props.closeModal, 
        loginInvalid: this.props.add,
        passwordInvalid: false
      };

      this.handleChangeSource = this.handleChangeSource.bind(this);
      this.handleChangeLogin = this.handleChangeLogin.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeEmail = this.handleChangeEmail.bind(this);
      this.handleChangePassword = this.handleChangePassword.bind(this);
      this.handleChangeConfirmPassword = this.handleChangeConfirmPassword.bind(this);
      this.handleChangeEnabled = this.handleChangeEnabled.bind(this);
      this.updateScopes = this.updateScopes.bind(this);
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      var user = nextProps.user;
      if (nextProps.add) {
        user = {
          source: "database",
          name: "",
          login: "",
          email: "",
          enabled: true,
          scope: []
        }
      }
      user.password = "";
      user.confirmPassword = "";
      this.setState({
        show: nextProps.show, 
        add: nextProps.add, 
        user: user, 
        closeModal: nextProps.closeModal, 
        loginInvalid: nextProps.add,
        passwordInvalid: false
      });
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.add, this.state.user);
      }
      this.setState({show: false});
    }
    
    handleChangeSource (event) {
      var newUser = $.extend({}, this.state.user);
      newUser.source = event.target.value;
      this.setState({user: newUser});
    }
    
    handleChangeLogin (event) {
      var isInvalid = !event.target.value;
      var newUser = $.extend({}, this.state.user);
      newUser.login = event.target.value || "";
      this.setState({user: newUser, loginInvalid: isInvalid});
    }
    
    handleChangeName (event) {
      var newUser = $.extend({}, this.state.user);
      newUser.name = event.target.value || "";
      this.setState({user: newUser});
    }
    
    handleChangeEmail (event) {
      var newUser = $.extend({}, this.state.user);
      newUser.email = event.target.value || "";
      this.setState({user: newUser});
    }
    
    handleChangePassword (event) {
      var isInvalid = (!!event.target.value || !!this.state.user.confirmPassword) && (event.target.value !== this.state.user.confirmPassword || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.user);
      newUser.password = event.target.value || "";
      this.setState({user: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeConfirmPassword (event) {
      var isInvalid = (!!this.state.user.password || !!event.target.value) && (this.state.user.password !== event.target.value || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.user);
      newUser.confirmPassword = event.target.value || "";
      this.setState({user: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeEnabled (event) {
      var newUser = $.extend({}, this.state.user);
      newUser.enabled = !newUser.enabled;
      this.setState({user: newUser});
    }
    
    updateScopes (scopes) {
      var newUser = $.extend({}, this.state.user);
      newUser.scope = scopes;
      this.setState({user: newUser});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>User</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="userSource">Backend</label>
              </div>
              <div className="col-md-6">
                <select className="form-control" name="userSource" id="userSource" value={this.state.user.source} onChange={this.handleChangeSource} data-toggle="tooltip" title="Backend to store the user">
                  <option value="database">Database</option>
                  <option value="ldap">LDAP</option>
                </select>
              </div>
            </div>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="userLogin">Login</label>
              </div>
              <div className={this.state.loginInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" type="text" name="userLogin" id="userLogin" disabled={!this.state.add?"disabled":""} placeholder="User Login" value={this.state.user.login} onChange={this.handleChangeLogin} data-toggle="tooltip" title="User login must be unique and can't be changed after creation"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userPassword">Password</label>
              </div>
              <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="userPassword" 
                       id="userPassword" 
                       placeholder="User password" 
                       onChange={this.handleChangePassword} 
                       value={this.state.user.password} 
                       data-toggle="tooltip" 
                       title="Password must be at least 8 characters, leave empty if you don't want to set or change the password">
                 </input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userPasswordConfirm">Confirm password</label>
              </div>
              <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="userPasswordConfirm" 
                       id="userPasswordConfirm" 
                       placeholder="Confirm User password" 
                       onChange={this.handleChangeConfirmPassword} 
                       value={this.state.user.confirmPassword} 
                       data-toggle="tooltip" 
                       title="must exactly match password"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userName">Name</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="text" name="userName" id="userName" placeholder="Fullname" value={this.state.user.name} onChange={this.handleChangeName} data-toggle="tooltip" title="User full name"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userEmail">E-mail</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" 
                       type="text" 
                       name="userEmail" 
                       id="userEmail" 
                       placeholder="User e-mail" 
                       value={this.state.user.email} 
                       onChange={this.handleChangeEmail} 
                       data-toggle="tooltip" 
                       title="User e-mail address, used to send password reset">
                 </input>
              </div>
            </div>
            <ScopeManagement scopes={this.state.user.scope} updateScopes={this.updateScopes} />
            <div className="row top-buffer">
              <div className="col-md-6">
                <label for="userEnabled">Enabled</label>
              </div>
              <div className="col-md-6">
                <Checkbox id="userEnabled" validationState="success" checked={this.state.user.enabled?true:false} onChange={this.handleChangeEnabled} data-toggle="tooltip" title="A disabled user can't log in or access its profile"></Checkbox>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)} disabled={this.state.passwordInvalid||this.state.loginInvalid?true:false}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  /**
   * Client table management component
   */
  class ClientTable extends React.Component {
    constructor(props) {
      super(props);
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {
        clients: this.props.clients, 
        editClient: null
      };
      
      this.runSearch = this.runSearch.bind(this);
      this.openModalAdd = this.openModalAdd.bind(this);
      this.saveClient = this.saveClient.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.openModalDelete = this.openModalDelete.bind(this);
      this.deleteClient = this.deleteClient.bind(this);
      this.openAlertModal = this.openAlertModal.bind(this);
    }
    
    openModalAdd () {
      ReactDOM.render(
        <ClientEditModal show={true} add={true} closeModal={this.saveClient} />,
        document.getElementById('modal')
      );
    }
    
    openModalEdit (client) {
      var cloneClient = $.extend({}, client);
      ReactDOM.render(
        <ClientEditModal show={true} add={false} client={cloneClient} closeModal={this.saveClient} />,
        document.getElementById('modal')
      );
    }
    
    openModalDelete (client) {
      var message = "Are your sure you want to delete client '" + client.name + "'";
      ReactDOM.render(
        <ConfirmModal show={true} title={"Client"} message={message} onClose={this.deleteClient} />,
        document.getElementById('modal')
      );
      this.setState({editClient: client});
    }
    
    openAlertModal (message) {
      ReactDOM.render(
        <MessageModal show={true} title={"Client"} message={message} />,
        document.getElementById('modal')
      );
    }
    
    deleteClient (result) {
      var self = this;
      if (result) {
        APIRequest("DELETE", "/client/" + this.state.editClient.client_id)
        .then(function (result) {
            var clients = self.state.clients;
            for (var key in clients) {
              if (clients[key].client_id === self.state.editClient.client_id) {
                clients.splice(key, 1);
                break;
              }
            };
            self.setState({clients: clients});
            self.openAlertModal("Client deleted");
        })
        .fail(function (error) {
          self.openAlertModal("Error deleting client");
        });
      }
    }
    
    saveClient (add, client) {
      var self = this;
      if (!client.password) {
        delete(client.password);
      }
      if (add) {
        APIRequest("GET", "/client/" + client.client_id)
        .then(function (result) {
          self.openAlertModal("Error, client_id '" + client.client_id + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "/client/", client)
          .then(function (result) {
            var clients = self.state.clients;
            clients.push(client);
            self.setState({clients: clients});
            self.openAlertModal("Client created");
          })
          .fail(function (error) {
            self.openAlertModal("Error adding client");
          });
        });
        
      } else {
        APIRequest("PUT", "/client/" + client.client_id, client)
        .then(function () {
          var clients = self.state.clients;
          for (var key in clients) {
            if (clients[key].client_id === client.client_id) {
              clients[key] = client;
            }
          };
          self.setState({clients: clients});
          self.openAlertModal("Client updated");
          })
          .fail(function (error) {
            self.openAlertModal("Error updating client");
        });
      }
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "/client/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({clients: result});
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching clients");
        });
      } else {
        APIRequest("GET", "/client/" + "?limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({clients: result});
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching clients");
        });
      }
    }

    render() {
      var self = this;
      var rows = [];
      this.state.clients.forEach(function(client, index) {
        rows.push(
          <ClientRow client={client} openModalEdit={self.openModalEdit} openModalDelete={self.openModalDelete} key={index} />
        );
      });
      
      return (
        <div>
          <ListNavigation updateNavigation={this.runSearch} />
          <Button className="btn btn-default" onClick={this.openModalAdd} data-toggle="tooltip" title="Add a new client">
            <i className="fa fa-plus"></i>
          </Button>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Source</th>
                <th>Client Id</th>
                <th>Name</th>
                <th>Description</th>
                <th>Confidential</th>
                <th>Scopes</th>
                <th>Authorization Types</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }
  
  function ClientRow (props) {
    return (
      <tr className={!props.client.enabled?"danger":""}>
        <td>{props.client.source}</td>
        <td>{props.client.client_id}</td>
        <td>{props.client.name}</td>
        <td>{props.client.description}</td>
        <td>{String(props.client.confidential)}</td>
        <td>{props.client.scope.join(", ")}</td>
        <td>{props.client.authorization_type.join(", ")}</td>
        <td>{String(props.client.enabled)}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.client)} data-toggle="tooltip" title="Edit client">
                <i className="fa fa-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.client)} data-toggle="tooltip" title="Delete client">
                <i className="fa fa-trash"></i>
              </Button>
            </div>
          </div>
        </td>
      </tr>
    );
  }
  
  class ClientEditModal extends React.Component {
    constructor(props) {
      super(props);
      var client = props.client;
      if (props.add) {
        client = {
          source: "database",
          name: "",
          description: "",
          client_id: "",
          confidential: false,
          enabled: true,
          redirect_uri: [],
          scope: [],
          authorization_type: []
        }
      }
      client.password = "";
      client.confirmPassword = "";
      this.state = {
        show: props.show, 
        add: this.props.add, 
        client: client, 
        closeModal: this.props.closeModal, 
        nameInvalid: this.props.add, 
        clientIdInvalid: this.props.add,
        redirectUriNameInvalid: true,
        redirectUriInvalid: true,
      };

      this.handleChangeSource = this.handleChangeSource.bind(this);
      this.handleChangeClientId = this.handleChangeClientId.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeDescription = this.handleChangeDescription.bind(this);
      this.handleChangeConfidential = this.handleChangeConfidential.bind(this);
      this.handleChangePassword = this.handleChangePassword.bind(this);
      this.handleChangeConfirmPassword = this.handleChangeConfirmPassword.bind(this);
      this.handleChangeRedirectUriName = this.handleChangeRedirectUriName.bind(this);
      this.handleChangeRedirectUri = this.handleChangeRedirectUri.bind(this);
      this.addRedirectUri = this.addRedirectUri.bind(this);
      this.removeRedirectUri = this.removeRedirectUri.bind(this);
      this.handleChangeEnabled = this.handleChangeEnabled.bind(this);
      this.updateScopes = this.updateScopes.bind(this);
      this.updateAuthTypes = this.updateAuthTypes.bind(this);
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      var client = nextProps.client;
      if (nextProps.add) {
        client = {
          source: "database",
          name: "",
          description: "",
          client_id: "",
          confidential: false,
          enabled: true,
          redirect_uri: [],
          scope: [],
          authorization_type: []
        }
      }
      client.password = "";
      client.confirmPassword = "";
      this.setState({
        show: nextProps.show, 
        add: nextProps.add, 
        client: client, 
        closeModal: nextProps.closeModal, 
        nameInvalid: nextProps.add, 
        clientIdInvalid: nextProps.add,
        redirectUriNameInvalid: true,
        redirectUriInvalid: true
      });
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.add, this.state.client);
      }
      this.setState({show: false});
    }
    
    handleChangeSource (event) {
      var newClient = $.extend({}, this.state.client);
      newClient.source = event.target.value;
      this.setState({client: newClient});
    }
    
    handleChangeClientId (event) {
      var isInvalid = !event.target.value;
      var newClient = $.extend({}, this.state.client);
      newClient.client_id = event.target.value || "";
      this.setState({client: newClient, clientIdInvalid: isInvalid});
    }
    
    handleChangeName (event) {
      var isInvalid = !event.target.value;
      var newClient = $.extend({}, this.state.client);
      newClient.name = event.target.value || "";
      this.setState({client: newClient, nameInvalid: isInvalid});
    }
    
    handleChangeDescription (event) {
      var newClient = $.extend({}, this.state.client);
      newClient.description = event.target.value || "";
      this.setState({client: newClient});
    }
    
    handleChangeRedirectUriName (event) {
      var isInvalid = !event.target.value.length > 0;
      this.setState({redirectUriName: event.target.value || "", redirectUriNameInvalid: isInvalid});
    }
    
    handleChangeRedirectUri (event) {
      var isInvalid = !event.target.value.startsWith("http://") && !event.target.value.startsWith("https://");
      this.setState({redirectUri: event.target.value || "", redirectUriInvalid: isInvalid});
    }
    
    addRedirectUri (event) {
      if (this.state.redirectUriName.length > 0 && (this.state.redirectUri.startsWith("http://") || this.state.redirectUri.startsWith("https://"))) {
        var newClient = $.extend({}, this.state.client);
        newClient.redirect_uri.push({name: this.state.redirectUriName, uri: this.state.redirectUri});
        this.setState({client: newClient});
      }
    }
    
    handleChangeConfidential (event) {
      var newClient = $.extend({}, this.state.client);
      newClient.confidential = !newClient.confidential;
      var isInvalid = newClient.confidential && (this.state.client.password !== this.state.client.confirmPassword || !this.state.client.password || this.state.client.password.length < 8);
      this.setState({client: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangePassword (event) {
      var isInvalid = this.state.client.confidential && (event.target.value !== this.state.client.confirmPassword || event.target.value.length < 8);
      var newClient = $.extend({}, this.state.client);
      newClient.password = event.target.value || "";
      this.setState({client: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangeConfirmPassword (event) {
      var isInvalid = this.state.client.confidential && (event.target.value !== this.state.client.password || !this.state.client.password || this.state.client.password.length < 8);
      var newClient = $.extend({}, this.state.client);
      newClient.confirmPassword = event.target.value || "";
      this.setState({client: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangeEnabled (event) {
      var newClient = $.extend({}, this.state.client);
      newClient.enabled = !newClient.enabled;
      this.setState({client: newClient});
    }
    
    updateScopes (scopes) {
      var newClient = $.extend({}, this.state.resource);
      newClient.scope = scopes;
      this.setState({resource: newClient});
    }
    
    updateAuthTypes (authTypes) {
      var newClient = $.extend({}, this.state.resource);
      newClient.authorization_type = authTypes;
      this.setState({resource: newClient});
    }
    
    removeRedirectUri (redirectUri, event) {
      event.preventDefault();
      var client = this.state.client;
      client.redirect_uri.splice(client.redirect_uri.indexOf(client.redirectUri), 1);
      this.setState({client: client});
    }
    
    render () {
      var clientRedirectUriList = [];
      var self = this;
      this.state.client.redirect_uri.forEach(function (redirect_uri, index) {
        clientRedirectUriList.push(
          <span className="tag label label-info hide-overflow" key={index} data-toggle="tooltip" title={redirect_uri.uri}>
            <a href="" onClick={(evt) => self.removeRedirectUri(redirect_uri.name, evt)}>
              <i className="remove fa fa-trash fa-white"></i>
            </a>
            <span>&nbsp;{redirect_uri.name + " (" + redirect_uri.uri + ")"}</span>
          </span>
        );
      });
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>Client</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="clientSource">Backend</label>
              </div>
              <div className="col-md-6">
                <select className="form-control" name="clientSource" id="clientSource" value={this.state.client.source} onChange={this.handleChangeSource} data-toggle="tooltip" title="Backend used to store client">
                  <option value="ldap">LDAP</option>
                  <option value="database">Database</option>
                </select>
              </div>
            </div>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="clientId">Client Id</label>
              </div>
              <div className={this.state.clientIdInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text" 
                       name="clientId" 
                       id="clientId" 
                       disabled={!this.state.add?"disabled":""} 
                       placeholder="Client Id" 
                       value={this.state.client.client_id} 
                       onChange={this.handleChangeClientId}
                       data-toggle="tooltip" 
                       title="client_id must be unique and can't be changed after creation"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="clientName">Name</label>
              </div>
              <div className={this.state.nameInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text"
                       name="clientName" 
                       id="clientName" 
                       placeholder="Fullname" 
                       value={this.state.client.name} 
                       onChange={this.handleChangeName}
                       data-toggle="tooltip" 
                       title="name can't be changed after creation"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="clientDescription">Description</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" 
                       type="text" 
                       name="clientDescription" 
                       id="clientDescription" 
                       placeholder="Client description" 
                       value={this.state.client.description} 
                       onChange={this.handleChangeDescription}
                       data-toggle="tooltip" 
                       title="Client description"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label>Confidential</label>
              </div>
              <div className="col-md-6">
                <Checkbox validationState="success" checked={this.state.client.confidential?true:false} onChange={this.handleChangeConfidential}></Checkbox>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="clientPassword">Password</label>
              </div>
              <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="clientPassword" 
                       id="clientPassword" 
                       placeholder="User password" 
                       disabled={this.state.client.confidential?false:true}
                       onChange={this.handleChangePassword} 
                       value={this.state.client.password}
                       data-toggle="tooltip" 
                       title="Password must be at least 8 characters, leave empty if you don't want to set or change the password"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="clientPasswordConfirm">Confirm password</label>
              </div>
              <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="clientPasswordConfirm" 
                       id="clientPasswordConfirm" 
                       placeholder="Confirm User password" 
                       disabled={this.state.client.confidential?false:true}
                       onChange={this.handleChangeConfirmPassword} 
                       value={this.state.client.confirmPassword}
                       data-toggle="tooltip" 
                       title="must exactly match password"></input>
              </div>
            </div>
            <ClientAuthTypeManagement authorizationTypes={this.state.client.authorization_type} updateAuthTypes={this.updateAuthTypes} />
            <ScopeManagement scopes={this.state.client.scope} updateScopes={this.updateScopes} />
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="clientScope">Redirect URIs</label>
              </div>
              <div className="col-md-6">
                <div className={this.state.redirectUriInvalid?"has-error":""}>
                  <input className="form-control" 
                         type="text" 
                         placeholder="URI" 
                         data-toggle="tooltip" 
                         title="Redirect uri must start with http:// or https://" 
                         value={this.state.redirectUri} 
                         onChange={this.handleChangeRedirectUri}></input>
                </div>
                <div>
                  <div className={this.state.redirectUriNameInvalid?"input-group has-error":"input-group"}>
                    <input className="form-control" 
                           type="text" 
                           placeholder="Name" 
                           value={this.state.redirectUriName} 
                           onChange={this.handleChangeRedirectUriName}
                           data-toggle="tooltip" 
                           title="Name you use for this redirect_uri"></input>
                    <div className="input-group-btn ">
                      <Button name="addScope" 
                              id="addScope" 
                              className="btn btn-default" 
                              disabled={this.state.redirectUriNameInvalid||this.state.redirectUriInvalid?true:false}
                              onClick={this.addRedirectUri}>
                        <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
              </div>
              <div className="col-md-6" id="clientRedirectUriList">
              {clientRedirectUriList}
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label>Enabled</label>
              </div>
              <div className="col-md-6">
                <Checkbox validationState="success" checked={this.state.client.enabled?true:false} onChange={this.handleChangeEnabled}></Checkbox>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true, this.state.client)} disabled={this.state.passwordInvalid||this.state.clientIdInvalid||this.state.nameInvalid||this.state.client.redirect_uri.length===0?true:false}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  class ClientAuthTypeManagement extends React.Component {
    constructor(props) {
      super(props);
      
      var authTypeSelected = "";
      if (authorizationTypeList.length > 0) {
        authTypeSelected = authorizationTypeList[0].name;
      }
      this.state = {authorizationTypes: props.authorizationTypes, authTypeSelected: authTypeSelected, updateAuthTypes: props.updateAuthTypes};

      this.handleChangeAuthTypeSelected = this.handleChangeAuthTypeSelected.bind(this);
      this.addAuthType = this.addAuthType.bind(this);
      this.removeAuthType = this.removeAuthType.bind(this);
    }
    
    handleChangeAuthTypeSelected (event) {
      this.setState({authTypeSelected: event.target.value});
    }
    
    removeAuthType (authType, event) {
      event.preventDefault();
      var authorizationTypes = this.state.authorizationTypes;
      authorizationTypes.splice(authorizationTypes.indexOf(authType), 1);
      this.setState({authorizationTypes: authorizationTypes});
      this.state.updateAuthTypes(authorizationTypes);
    }
    
    addAuthType () {
      var authorizationTypes = this.state.authorizationTypes;
      if (authorizationTypes.indexOf(this.state.authTypeSelected) == -1) {
        this.setState({authorizationTypes: authorizationTypes});
        authorizationTypes.push(this.state.authTypeSelected);
      }
      this.state.updateAuthTypes(authorizationTypes);
    }
    
    render () {
      var self = this;
      var allAuthTypeList = [];
      authorizationTypeList.forEach(function (authType, index) {
        allAuthTypeList.push(<option value={authType.name} key={index}>{authType.name}</option>)
      });
      var curAuthTypeList = [];
      this.state.authorizationTypes.forEach(function (authType, index) {
        curAuthTypeList.push(
          <span className="tag label label-info hide-overflow" key={index}>
            <span>{authType}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeAuthType(authType, evt)}>
              <i className="remove fa fa-trash fa-white"></i>
            </a>
          </span>
        );
      });
      return (
        <div>
          <div className="row top-buffer">
            <div className="col-md-6">
              <label htmlFor="userAuthType">Authorization types</label>
            </div>
            <div className="col-md-6">
              <div className="input-group">
                <select id="userAuthType" name="userAuthType" className="form-control" value={this.state.authTypeSelected} onChange={this.handleChangeAuthTypeSelected} data-toggle="tooltip" title="Authorization types to allow for this client">
                  {allAuthTypeList}
                </select>
                <div className="input-group-btn ">
                  <Button name="addAuthType" id="addAuthType" className="btn btn-default" onClick={this.addAuthType}>
                    <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                  </Button>
                </div>
              </div>
            </div>
          </div>
          <div className="row top-buffer">
            <div className="col-md-6">
            </div>
            <div className="col-md-6" id="userAuthTypeValue">
            {curAuthTypeList}
            </div>
          </div>
        </div>
      );
    }
  }

  /**
   * Scope table management component
   */
  class ScopeTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        scopes: this.props.scopes, 
        showModal: false, 
        editScope: { name: "", description: "" }, 
        add: false, 
        nameInvalid: false,
        showConfirmModal: false,
        messageConfirmModal: "",
        showAlertModal: false,
        messageAlertModal: ""
      };
      
      // Modal functions
      this.openModalAdd = this.openModalAdd.bind(this);
      this.closeScopeModal = this.closeScopeModal.bind(this);
      this.saveScope = this.saveScope.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeDescription = this.handleChangeDescription.bind(this);
      
      this.openModalDelete = this.openModalDelete.bind(this);
      this.confirmDelete = this.confirmDelete.bind(this);
      
      this.openAlertModal = this.openAlertModal.bind(this);
    }
    
    openModalAdd (event) {
      event.preventDefault();
      ReactDOM.render(
        <ScopeEditModal show={true} add={true} scope={{name: "", description: ""}} closeModal={this.saveScope} />,
        document.getElementById('modal')
      );
    }
    
    openModalEdit (scope) {
      var cloneScope = $.extend({}, scope);
      this.setState({editScope: cloneScope});
      ReactDOM.render(
        <ScopeEditModal show={true} add={false} scope={cloneScope} closeModal={this.saveScope} />,
        document.getElementById('modal')
      );
    }
    
    openModalDelete (scope) {
      var message = "Are your sure you want to delete scope '" + scope.name + "'";
      ReactDOM.render(
        <ConfirmModal show={true} title={"Delete scope"} message={message} onClose={this.confirmDelete} />,
        document.getElementById('modal')
      );
      this.setState({editScope: scope});
    }
    
    openAlertModal (message) {
      ReactDOM.render(
        <MessageModal show={true} title={"Scope"} message={message} />,
        document.getElementById('modal')
      );
    }
    
    confirmDelete (result) {
      if (result) {
        var self = this;
        APIRequest("DELETE", "/scope/" + this.state.editScope.name)
        .then(function (result) {
            var scopes = self.state.scopes;
            for (var key in scopes) {
              if (scopes[key].name === self.state.editScope.name) {
                scopes.splice(key, 1);
                break;
              }
            };
            self.setState({scopes: scopes});
            self.openAlertModal("Scope deleted");
        })
        .fail(function (error) {
          self.openAlertModal("Error deleting scope");
        });
      }
    }
    
    closeScopeModal(result, value) {
      this.setState({showModal: false});
    }
    
    saveScope (add, scope) {
      var self = this;
      if (add) {
        APIRequest("GET", "/scope/" + scope.name)
        .then(function (result) {
          self.openAlertModal("Error, scope '" + scope.name + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "/scope/", scope)
          .then(function (result) {
            var scopes = self.state.scopes;
            scopes.push(scope);
            self.setState({scopes: scopes});
            self.openAlertModal("Scope created");
          })
          .fail(function (error) {
            self.openAlertModal("Error adding scope");
          });
        });
      } else {
        APIRequest("PUT", "/scope/" + scope.name, scope)
        .then(function () {
          var scopes = self.state.scopes;
          for (var key in scopes) {
            if (scopes[key].name === scope.name) {
              scopes[key] = scope;
            }
          };
          self.setState({scopes: scopes});
          self.openAlertModal("Scope updated");
          })
          .fail(function (error) {
            self.openAlertModal("Error updating scope");
        });
      }
    }
    
    handleChangeName (event) {
      var isInvalid = !event.target.value;
      var newScope = $.extend({}, this.state.editScope);
      newScope.name = event.target.value || "";
      this.setState({editScope: newScope, nameInvalid: isInvalid});
    }
    
    handleChangeDescription (event) {
      var newScope = $.extend({}, this.state.editScope);
      newScope.description = event.target.value || "";
      this.setState({editScope: newScope});
    }
    
    render() {
      var self = this;
      var rows = [];
      this.state.scopes.forEach(function(scope, index) {
        rows.push(<ScopeRow scope={scope} openModalEdit={self.openModalEdit} openModalDelete={self.openModalDelete} key={index}/>);
      });
      
      return (
        <div>
          <Button className="btn btn-default" onClick={this.openModalAdd} data-toggle="tooltip" title="Add a new scope">
            <i className="fa fa-plus"></i>
          </Button>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }

  function ScopeRow (props) {
    return (
      <tr>
        <td>{props.scope.name}</td>
        <td>{props.scope.description}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.scope)} data-toggle="tooltip" title="Edit scope">
                <i className="fa fa-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.scope)} data-toggle="tooltip" title="Remove scope">
                <i className="fa fa-trash"></i>
              </Button>
            </div>
          </div>
        </td>
      </tr>
    );
  }
  
  class ScopeEditModal extends React.Component {
    constructor(props) {
      super(props);
      this.state = {show: props.show, add: this.props.add, scope: this.props.scope, closeModal: this.props.closeModal, nameInvalid: this.props.add};
      
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeDescription = this.handleChangeDescription.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, add: nextProps.add, scope: nextProps.scope, closeModal: nextProps.closeModal});
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.add, this.state.scope);
      }
      this.setState({show: false});
    }
    
    handleChangeName (event) {
      var isInvalid = !event.target.value;
      var newScope = $.extend({}, this.state.scope);
      newScope.name = event.target.value || "";
      this.setState({scope: newScope, nameInvalid: isInvalid});
    }
    
    handleChangeDescription (event) {
      var newScope = $.extend({}, this.state.scope);
      newScope.description = event.target.value || "";
      this.setState({scope: newScope});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>Scope</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="scopeName">Name</label>
              </div>
              <div className={this.state.nameInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text" 
                       name="scopeName" 
                       id="scopeName" 
                       disabled={!this.state.add?"disabled":""} 
                       placeholder="Name" 
                       value={this.state.scope.name} 
                       onChange={this.handleChangeName}
                       data-toggle="tooltip" 
                       title="Scope name must be unique and can't be changed after creation"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="scopeDescription">Description</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" 
                       type="text" 
                       name="scopeDescription" 
                       id="scopeDescription" 
                       placeholder="Description" 
                       value={this.state.scope.description} 
                       onChange={this.handleChangeDescription}
                       data-toggle="tooltip" 
                       title="Scope description"></input>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)} disabled={this.state.nameInvalid?true:false}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  /**
   * Resource table management component
   */
  class ResourceTable extends React.Component {
    constructor(props) {
      super(props);
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {
        resources: this.props.resources,
        editResource: {}
      };
      
      // Modal functions
      this.openModalAdd = this.openModalAdd.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.openModalDelete = this.openModalDelete.bind(this);
      this.openAlertModal = this.openAlertModal.bind(this);
      
      this.confirmDelete = this.confirmDelete.bind(this);
      this.saveResource = this.saveResource.bind(this);
    }
    
    openModalAdd () {
      ReactDOM.render(
        <ResourceEditModal show={true} add={true} resource={{name: "", description: "", uri: "", enabled: true, scope: []}} closeModal={this.saveResource} />,
        document.getElementById('modal')
      );
    }
    
    openModalEdit (resource) {
      var cloneResource = $.extend({}, resource);
      this.setState({editResource: cloneResource});
      ReactDOM.render(
        <ResourceEditModal show={true} add={false} resource={cloneResource} closeModal={this.saveResource} />,
        document.getElementById('modal')
      );
    }
    
    openModalDelete (resource) {
      var message = "Are your sure you want to delete resource '" + resource.name + "'";
      ReactDOM.render(
        <ConfirmModal show={true} title={"Add resource"} message={message} onClose={this.confirmDelete} />,
        document.getElementById('modal')
      );
      this.setState({editResource: resource});
    }
    
    openAlertModal (message) {
      ReactDOM.render(
        <MessageModal show={true} title={"Add resource"} message={message} />,
        document.getElementById('modal')
      );
    }
    
    confirmDelete (result) {
      if (result) {
        var self = this;
        APIRequest("DELETE", "/resource/" + this.state.editResource.name)
        .then(function (result) {
            var resources = self.state.resources;
            for (var key in resources) {
              if (resources[key].name === self.state.editResource.name) {
                resources.splice(key, 1);
                break;
              }
            };
            self.setState({resources: resources});
            self.openAlertModal("Resource deleted");
        })
        .fail(function (error) {
          self.openAlertModal("Error deleting resource");
        });
      }
    }
    
    saveResource (add, resource) {
      var self = this;
      if (add) {
        APIRequest("GET", "/resource/" + resource.name)
        .then(function (result) {
          self.openAlertModal("Error, resource '" + resource.name + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "/resource/", resource)
          .then(function (result) {
            var resources = self.state.resources;
            resources.push(resource);
            self.setState({resources: resources});
            self.openAlertModal("Resource created");
          })
          .fail(function (error) {
            self.openAlertModal("Error adding resource");
          });
        })
        
      } else {
        APIRequest("PUT", "/resource/" + resource.name, resource)
        .then(function () {
          var resources = self.state.resources;
          for (var key in resources) {
            if (resources[key].name === resource.name) {
              resources[key] = resource;
            }
          };
          self.setState({resources: resources});
          self.openAlertModal("Resource updated");
          })
          .fail(function (error) {
            self.openAlertModal("Error updating resource");
        });
      }
    }
    
    render() {
      var self = this;
      var rows = [];
      this.state.resources.forEach(function(resource, index) {
        rows.push(
          <ResourceRow resource={resource} key={index} openModalEdit={self.openModalEdit} openModalDelete={self.openModalDelete} />
        );
      });
      
      return (
        <div>
          <Button className="btn btn-default" onClick={this.openModalAdd} data-toggle="tooltip" title="Add a new resource">
            <i className="fa fa-plus"></i>
          </Button>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>URI</th>
                <th>Scopes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }
  
  function ResourceRow (props) {
    return (
      <tr>
        <td>{props.resource.name}</td>
        <td>{props.resource.description}</td>
        <td><a href="{props.resource.uri}" title={props.resource.description}>{props.resource.uri}</a></td>
        <td>{props.resource.scope.join(", ")}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.resource)} data-toggle="tooltip" title="Edit resource">
                <i className="fa fa-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.resource)} data-toggle="tooltip" title="Remove resource">
                <i className="fa fa-trash"></i>
              </Button>
            </div>
          </div>
        </td>
      </tr>
    );
  }
  
  class ResourceEditModal extends React.Component {
    constructor(props) {
      super(props);
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {show: props.show, add: this.props.add, resource: this.props.resource, selectedScope: selectedScope, closeModal: this.props.closeModal, nameInvalid: this.props.add, uriInvalid: this.props.add};
      
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeDescription = this.handleChangeDescription.bind(this);
      this.handleChangeUri = this.handleChangeUri.bind(this);
      this.updateScopes = this.updateScopes.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, add: nextProps.add, resource: nextProps.resource, closeModal: nextProps.closeModal});
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.add, this.state.resource);
      }
      this.setState({show: false});
    }
    
    handleChangeName (event) {
      var isInvalid = !event.target.value;
      var newResource = $.extend({}, this.state.resource);
      newResource.name = event.target.value || "";
      this.setState({resource: newResource, nameInvalid: isInvalid});
    }
    
    handleChangeDescription (event) {
      var newResource = $.extend({}, this.state.resource);
      newResource.description = event.target.value || "";
      this.setState({resource: newResource});
    }
    
    handleChangeUri (event) {
      var isInvalid = !event.target.value;
      var newResource = $.extend({}, this.state.resource);
      newResource.uri = event.target.value || "";
      this.setState({resource: newResource, uriInvalid: isInvalid});
    }
    
    updateScopes (scopes) {
      var newResource = $.extend({}, this.state.resource);
      newResource.scope = scopes;
      this.setState({resource: newResource});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>Resource</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="resourceName">Name</label>
              </div>
              <div className={this.state.nameInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text" 
                       name="resourceName" 
                       id="resourceName" 
                       disabled={!this.state.add} 
                       placeholder="Name" 
                       value={this.state.resource.name} 
                       onChange={this.handleChangeName}
                       data-toggle="tooltip" 
                       title="Resource name can't be changed after creation"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="resourceDescription">Description</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" 
                       type="text" 
                       name="resourceDescription" 
                       id="resourceDescription" 
                       placeholder="Description" 
                       value={this.state.resource.description} 
                       onChange={this.handleChangeDescription}
                       data-toggle="tooltip" 
                       title="Resource description"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="resourceUri">URI</label>
              </div>
              <div className={this.state.uriInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text" 
                       name="resourceUri" 
                       id="resourceUri" 
                       placeholder="resource URI" 
                       value={this.state.resource.uri} 
                       onChange={this.handleChangeUri}
                       data-toggle="tooltip" 
                       title="URI to access resource"></input>
              </div>
            </div>
            <ScopeManagement scopes={this.state.resource.scope} updateScopes={this.updateScopes} />
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)} disabled={this.state.nameInvalid||this.state.uriInvalid?true:false}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }

  /**
   * User details component
   */
  function UserDetails (props) {
    return (
      <div>
        <h2>{props.user.name}</h2>
        <div className="well">
          <div className="row">
            <div className="col-md-3">
              <label>Name</label>
            </div>
            <div className="col-md-3">
              {props.user.name}
            </div>
            <div className="col-md-3">
              <label>Email</label>
            </div>
            <div className="col-md-3">
              {props.user.email}
            </div>
          </div>
          <div className="row">
            <div className="col-md-3">
              <label>Login</label>
            </div>
            <div className="col-md-3">
              {props.user.login}
            </div>
            <div className="col-md-3">
              <label>Scopes</label>
            </div>
            <div className="col-md-3">
              {props.user.scope.join(", ")}
            </div>
          </div>
          <div className="row">
            <div className="col-md-3">
              <label>Enabled</label>
            </div>
            <div className="col-md-3">
              {String(props.user.enabled)}
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  function UserSessionRow (props) {
    return (
      <tr className={!props.session.enabled?"danger":""}>
        <td>{props.session.ip_source}</td>
        <td>{(new Date(props.session.issued_at*1000)).toLocaleString()}</td>
        <td>{(new Date(props.session.last_seen*1000)).toLocaleString()}</td>
        <td>{(new Date(props.session.expired_at*1000)).toLocaleString()}</td>
        <td>{String(props.session.enabled)}</td>
        <td>
        {props.session.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.session, event)} data-toggle="tooltip" title="Revoke session">
            <i className="fa fa-trash"></i>
          </Button>:''}
        </td>
      </tr>
    );
  }
  
  class UserSessionTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {sessionList: this.props.sessionList};
      this.refreshSessionList = this.refreshSessionList.bind(this);
      this.openConfirmModal = this.openConfirmModal.bind(this);
      this.closeConfirmModal = this.closeConfirmModal.bind(this);
      
      this.state = {sessionList: this.props.sessionList, currentSession: {}}
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({sessionList: nextProps.sessionList});
    }
    
    refreshSessionList (valid, offset, limit) {
      var self = this;
      APIRequest("GET", "/user/" + this.props.login + "/session/?valid=" + (valid?valid:"") + "&offset=" + (offset?offset:"") + "&limit=" + (limit?limit:""))
      .then(function (result) {
        self.setState({sessionList: result});
      });
    }
    
    openConfirmModal (session, evt) {
      this.setState({currentSession: session});
      ReactDOM.render(
        <ConfirmModal show={true} title={"Disable session"} message={"Are you sure you want to disable this session?"} onClose={this.closeConfirmModal} />,
        document.getElementById('modal')
      );
    }
    
    closeConfirmModal (result, evt) {
      var self = this;
      if (result) {
        APIRequest("DELETE", "/user/" + this.props.login + "/session/", {session_hash: this.state.currentSession.session_hash})
        .then(function (result) {
          var currentSession = self.state.currentSession;
          currentSession.enabled = false;
          var sessionList = self.state.sessionList;
          sessionList.forEach(function (session) {
            if (session.session_hash === self.state.currentSession.session_hash) {
              session.enabled = false;
            }
          });
          self.setState({currentSession: currentSession, sessionList: sessionList});
          ReactDOM.render(
            <MessageModal show={true} title={"Session disabled"} message={"The session has been disabled"} />,
            document.getElementById('modal')
          );
        });
      }
    }
    
    render () {
      var rows = [];
      var self = this;
      this.state.sessionList.forEach(function (session, index) {
        rows.push(<UserSessionRow session={session} key={index} openModal={self.openConfirmModal}/>);
      });
      return (
        <div>
          <h3>Sessions&nbsp;</h3>
          <TokenNavigation updateNavigation={this.refreshSessionList} />
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Originiated IP Source</th>
                <th>Issued at</th>
                <th>Last seen</th>
                <th>Expires at</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }
  
  function UserTokenRow (props) {
    return (
      <tr className={!props.token.enabled?"danger":""}>
        <td>{props.token.ip_source}</td>
        <td>{props.token.authorization_type}</td>
        <td>{(new Date(props.token.issued_at*1000)).toLocaleString()}</td>
        <td>{(new Date(props.token.last_seen*1000)).toLocaleString()}</td>
        <td>{(new Date(props.token.expired_at*1000)).toLocaleString()}</td>
        <td>{String(props.token.enabled)}</td>
        <td>
        {props.token.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.token, event)} data-toggle="tooltip" title="Revoke token">
            <i className="fa fa-trash"></i>
          </Button>:''}
        </td>
      </tr>
    );
  }
  
  class UserTokenTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {tokenList: this.props.tokenList};
      this.refreshTokenList = this.refreshTokenList.bind(this);
      this.openConfirmModal = this.openConfirmModal.bind(this);
      this.closeConfirmModal = this.closeConfirmModal.bind(this);
      
      this.state = {tokenList: this.props.tokenList, currentToken: {}}
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({tokenList: nextProps.tokenList});
    }
    
    refreshTokenList (valid, offset, limit) {
      var self = this;
      APIRequest("GET", "/user/" + this.props.login + "/refresh_token/?valid=" + (valid?valid:"") + "&offset=" + (offset?offset:"") + "&limit=" + (limit?limit:""))
      .then(function (result) {
        self.setState({tokenList: result});
      });
    }
    
    openConfirmModal (token, evt) {
      this.setState({currentToken: token});
      ReactDOM.render(
        <ConfirmModal show={true} title={"Disable refresh token"} message={"Are you sure you want to disable this refresh token?"} onClose={this.closeConfirmModal} />,
        document.getElementById('modal')
      );
    }
    
    closeConfirmModal (result, evt) {
      var self = this;
      if (result) {
        APIRequest("DELETE", "/user/" + this.props.login + "/refresh_token/", {token_hash: this.state.currentToken.token_hash})
        .then(function (result) {
          var currentToken = self.state.currentToken;
          currentToken.enabled = false;
          var tokenList = self.state.tokenList;
          tokenList.forEach(function (token) {
            if (token.token_hash === self.state.currentToken.token_hash) {
              token.enabled = false;
            }
          });
          self.setState({currentToken: currentToken, tokenList: tokenList});
          ReactDOM.render(
            <MessageModal show={true} title={"Refresh token disabled"} message={"The refresh token has been disabled"} />,
            document.getElementById('modal')
          );
        });
      }
    }
    
    render () {
      var rows = [];
      var self = this;
      this.state.tokenList.forEach(function (token, index) {
        rows.push(<UserTokenRow token={token} key={index} openModal={self.openConfirmModal}/>);
      });
      return (
        <div>
          <h3>Refresh tokens&nbsp;</h3>
          <TokenNavigation updateNavigation={this.refreshTokenList} />
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Originiated IP Source</th>
                <th>Authorization type</th>
                <th>Issued at</th>
                <th>Last seen</th>
                <th>Expires at</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
          </table>
        </div>
      );
    }
  }
  
  /**
   * Login/Logout button component
   */
  function LoginInformation (props) {
    return (
      <h3><label className="label label-info">Hello {props.user.name}&nbsp;</label></h3>
    );
  }

  function ConnectMessage (props) {
    return (
      <h3><label className="label label-warning">Please log in to the application&nbsp;</label></h3>
    );
  }

  class LogoutButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogout = this.handleLogout.bind(this);
    }
    
    render() {
      return (<Button className="btn btn-primary btn-block" onClick={this.handleLogout} data-toggle="tooltip" title="log out">
        <i className="fa fa-sign-out" aria-hidden="true"></i>
        &nbsp;Log out
      </Button>);
    }
    
    handleLogout() {
      Cookies.remove(oauth.access_token_cookie);
      location.reload();
    }
  }

  class ProfileButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleProfile = this.handleProfile.bind(this);
    }
    
    render() {
      return (<Button type="button" className="btn btn-primary btn-block" onClick={this.handleProfile} data-toggle="tooltip" title="Edit my profile">
        <i className="fa fa-user" aria-hidden="true"></i>
        &nbsp;My profile
      </Button>);
    }
    
    handleProfile() {
      window.location = "profile.html";
    }
  }

  class LoginButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogin = this.handleLogin.bind(this);
    }
    
    render() {
      return (<Button type="button" className="btn btn-primary btn-block" onClick={this.handleLogin} data-toggle="tooltip" title="Log in">
        <i className="fa fa-sign-in" aria-hidden="true"></i>
        &nbsp;Log in
      </Button>);
    }
    
    handleLogin() {
      document.location = oauth.glewlwyd_server_url + oauth.api_prefix + "/auth?response_type=token&client_id="+oauth.client_id+"&redirect_uri="+oauth.redirect_uri+"&scope="+oauth.admin_scope;
    }
  }

  function LoginComponent (props) {
    if (props.user.loggedIn) {
      return (
        <div>
          <div className="row">
            <LogoutButton user={props.user} />
          </div>
          <div className="row">
            <ProfileButton user={props.user} />
          </div>
        </div>
      );
    } else {
      return (
        <div>
          <LoginButton />
        </div>
      );
    }
  }

  /**
   * Scope modal management
   */
  class ScopeManagement extends React.Component {
    constructor(props) {
      super(props);
      
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {scopes: props.scopes, selectedScope: selectedScope, updateScopes: props.updateScopes};

      this.handleChangeScopeSelected = this.handleChangeScopeSelected.bind(this);
      this.addScope = this.addScope.bind(this);
      this.removeScope = this.removeScope.bind(this);
    }
    
    handleChangeScopeSelected (event) {
      this.setState({selectedScope: event.target.value});
    }
    
    removeScope (scope, event) {
      event.preventDefault();
      var scopes = this.state.scopes;
      scopes.splice(scopes.indexOf(scope), 1);
      this.setState({scopes: scopes});
      this.state.updateScopes(scopes);
    }
    
    addScope (event) {
      var scopes = this.state.scopes;
      if (scopes.indexOf(this.state.selectedScope) == -1) {
        scopes.push(this.state.selectedScope);
        this.setState({scopes: scopes});
      }
      this.state.updateScopes(scopes);
    }
    
    render () {
      var self = this;
      var allScopeList = [];
      scopeList.forEach(function (scope) {
        allScopeList.push(<option value={scope.name} key={scope.name}>{scope.name}</option>)
      });
      var curScopeList = [];
      this.state.scopes.forEach(function (scope, index) {
        curScopeList.push(
          <span className="tag label label-info hide-overflow" key={index}>
            <span>{scope}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeScope(scope, evt)}>
              <i className="remove fa fa-trash fa-white"></i>
            </a>
          </span>
        );
      });
      return (
        <div>
          <div className="row top-buffer">
            <div className="col-md-6">
              <label htmlFor="userScope">Scopes</label>
            </div>
            <div className="col-md-6">
              <div className="input-group">
                <select id="userScope" name="userScope" className="form-control" value={this.state.scopeSelected} onChange={this.handleChangeScopeSelected}>
                  {allScopeList}
                </select>
                <div className="input-group-btn ">
                  <Button name="addScope" id="addScope" className="btn btn-default" onClick={this.addScope} data-toggle="tooltip" title="Add scope">
                    <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                  </Button>
                </div>
              </div>
            </div>
          </div>
          <div className="row top-buffer">
            <div className="col-md-6">
            </div>
            <div className="col-md-6" id="userScopeValue">
              {curScopeList}
            </div>
          </div>
        </div>
      );
    }
  }
  
  /**
   * List navigation management
   */
  class ListNavigation extends React.Component {
    constructor(props) {
      super(props);
      
      this.state = {search: "", limit: 10, offset: 0, updateNavigation: props.updateNavigation};

      this.handleChangeSearch = this.handleChangeSearch.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      this.handleSearch = this.handleSearch.bind(this);
    }

    handleChangeSearch (event) {
      this.setState({search: event.target.value});
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      this.setState({limit: limit});
      this.state.updateNavigation(this.state.search, this.state.offset, limit);
    }
    
    handlePreviousPage (event) {
      var offset = this.state.offset-this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.search, offset, this.state.limit);
    }
    
    handleNextPage (event) {
      var offset = this.state.offset+this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.search, offset, this.state.limit);
    }
    
    handleSearch (event) {
      event.preventDefault();
      this.state.updateNavigation(this.state.search, this.state.offset, this.state.limit);
    }
    
    render () {
      return (
        <div className="col-md-12 container">
          <div className="row">
            <div className="col-md-12 input-group">
              <span className="input-group-btn">
                <Button className="btn btn-default" 
                        disabled={(this.state.offset===0)} 
                        type="button" 
                        onClick={this.handlePreviousPage}
                        data-toggle="tooltip" 
                        title="Previous page">
                  <i className="icon-resize-small fa fa-chevron-left"></i>
                </Button>
              </span>
              <select className="form-control input-small" onChange={this.handleChangeLimit} value={this.state.limit} data-toggle="tooltip" title="Select page size">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
              <span className="input-group-btn paddingRight">
                <Button className="btn btn-default" type="button" onClick={this.handleNextPage} data-toggle="tooltip" title="Next page">
                  <i className="icon-resize-small fa fa-chevron-right"></i>
                </Button>
              </span>
              <form onSubmit={this.handleSearch}>
                <input type="text" className="form-control input-medium" placeholder="Search" value={this.state.search} onChange={this.handleChangeSearch} data-toggle="tooltip" title="Search value"/>
              </form>
              <span className="input-group-btn">
                <Button className="btn btn-default" onClick={this.handleSearch} data-toggle="tooltip" title="Run search">
                  <i className="fa fa-search"></i>
                </Button>
              </span>
            </div>
          </div>
          <div className="row">
            <div className="col-md-12 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
        </div>
      );
    }
  }
  
  class TokenNavigation extends React.Component {
    constructor(props) {
      super(props);
      
      this.state = {valid: "", limit: 10, offset: 0, updateNavigation: props.updateNavigation};

      this.handleChangeValid = this.handleChangeValid.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      this.handleRefresh = this.handleRefresh.bind(this);
    }

    handleChangeValid (event) {
      this.setState({valid: event.target.value});
      this.state.updateNavigation(event.target.value, this.state.offset, this.state.limit);
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      this.setState({limit: limit});
      this.state.updateNavigation(this.state.valid, this.state.offset, limit);
    }
    
    handlePreviousPage (event) {
      var offset = this.state.offset-this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.valid, offset, this.state.limit);
    }
    
    handleNextPage (event) {
      var offset = this.state.offset+this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.valid, offset, this.state.limit);
    }
    
    handleRefresh (event) {
      event.preventDefault();
      this.state.updateNavigation(this.state.valid, this.state.offset, this.state.limit);
    }
    
    render () {
      return (
        <div className="col-md-12 container">
          <div className="row">
            <div className="col-md-12 input-group">
              <span className="input-group-btn">
                <Button className="btn btn-default" 
                        disabled={(this.state.offset===0)} 
                        type="button" 
                        onClick={this.handlePreviousPage}
                        data-toggle="tooltip" 
                        title="Previous page">
                  <i className="icon-resize-small fa fa-chevron-left"></i>
                </Button>
              </span>
              <select className="form-control input-small" onChange={this.handleChangeLimit} value={this.state.limit} data-toggle="tooltip" title="Select page size">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
              <span className="input-group-btn paddingRight">
                <Button className="btn btn-default" type="button" onClick={this.handleNextPage} data-toggle="tooltip" title="Next page">
                  <i className="icon-resize-small fa fa-chevron-right"></i>
                </Button>
              </span>
              <select className="form-control input-small" onChange={this.handleChangeValid} value={this.state.valid} data-toggle="tooltip" title="Status">
                <option value="">Enabled and disabled</option>
                <option value="true">Enabled only</option>
                <option value="false">Disabled only</option>
              </select>
              <span className="input-group-btn paddingLeft">
                <Button className="btn btn-default" onClick={this.handleRefresh} data-toggle="tooltip" title="Refresh table">
                  <i className="icon-resize-small fa fa-refresh"></i>
                </Button>
              </span>
            </div>
          </div>
          <div className="row">
            <div className="col-md-12 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
        </div>
      );
    }
  }

  /**
   * Authentication type table management component
   */
  class AuthTypeEnableButton extends React.Component {
    constructor(props) {
      super(props);
      this.state = {enabled: this.props.authType.enabled, showAlertModal: false, messageAlertModal: ""};
      this.handleToggleAuthType = this.handleToggleAuthType.bind(this);

      this.openAlertModal = this.openAlertModal.bind(this);
      this.closeAlertModal = this.closeAlertModal.bind(this);
    }
    
    openAlertModal (message) {
      this.setState({showAlertModal: true, messageAlertModal: message});
    }
    
    closeAlertModal () {
      this.setState({showAlertModal: false});
    }
    
    render() {
      var modal = 
          <Modal show={this.state.showAlertModal} onHide={this.closeAlertModal}>
            <Modal.Header closeButton>
              <Modal.Title>Users</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageAlertModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.closeAlertModal}>Close</Button>
            </Modal.Footer>
          </Modal>
      if (this.state.enabled) {
        return (
        <div>
          <Button type="button" className="btn btn-danger" onClick={this.handleToggleAuthType} data-toggle="tooltip" title="Disable">Disable</Button>
          <Modal show={this.state.showAlertModal} onHide={this.closeAlertModal}>
            <Modal.Header closeButton>
              <Modal.Title>Authorization Type</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageAlertModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.closeAlertModal}>Close</Button>
            </Modal.Footer>
          </Modal>
        </div>);
      } else {
        return (
        <div>
          <Button type="button" className="btn btn-success" onClick={this.handleToggleAuthType} data-toggle="tooltip" title="Enable">Enable</Button>
          <Modal show={this.state.showAlertModal} onHide={this.closeAlertModal}>
            <Modal.Header closeButton>
              <Modal.Title>Authorization Type</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageAlertModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.closeAlertModal}>Close</Button>
            </Modal.Footer>
          </Modal>
        </div>);
      }
    }
    
    handleToggleAuthType () {
      var self = this;
      APIRequest("PUT","/authorization/" + this.props.authType.name, {description: this.props.authType.description, enabled: !this.state.enabled})
      .done(function (result) {
        self.setState(prevState => ({
          enabled: !prevState.enabled
        }));
        self.openAlertModal("Authorization type updated");
      })
      .fail(function (error) {
        self.openAlertModal("Error while changing authorization type");
      });
    }
  }

  class AuthorizationType extends React.Component {
    constructor(props) {
      super(props);
    }
    
    render () {
      return (
        <tr>
          <td>
            <label>{this.props.authType.name}</label>
          </td>
          <td>
            {this.props.authType.description}
          </td>
          <td>
            <AuthTypeEnableButton authType={this.props.authType} />
          </td>
        </tr>
      );
    }
  }

  function AuthorizationTypeList (props) {
    var rows = [];
    props.authTypeList.forEach(function(authType) {
      rows.push(<AuthorizationType authType={authType} key={authType.name} />);
    });
    return (
      <div className="well">
        <table className="table table-hover table-responsive">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
    );
  }
  
  /**
   * Modals
   */
  class MessageModal extends React.Component {
    constructor(props) {
      super(props);

      this.state = {show: this.props.show, title: this.props.title, message: this.props.message};
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, title: nextProps.title, message: nextProps.message});
    }
    
    closeModal () {
      this.setState({show: false});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={this.closeModal}>
          <Modal.Header closeButton>
            <Modal.Title>{this.state.title}</Modal.Title>
          </Modal.Header>
          <Modal.Body>
          {this.state.message}
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={this.closeModal}>Close</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }

  class SpinnerModal extends React.Component {
    constructor(props) {
      super(props);

      this.state = {show: this.props.show, message: this.props.message};
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, message: nextProps.message});
    }
    
    render () {
      return (
        <Modal show={this.state.show}>
          <Modal.Body>
          <h3><i className="fa fa-cog fa-spin"></i>{this.state.message}</h3>
          </Modal.Body>
        </Modal>
      );
    }
  }
  
  class ConfirmModal extends React.Component {
    constructor(props) {
      super(props);

      this.state = {show: this.props.show, title: this.props.title, message: this.props.message, onClose: this.props.onClose};
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, title: nextProps.title, message: nextProps.message, onClose: nextProps.onClose});
    }
    
    closeModal (result) {
      this.setState({show: false});
      this.state.onClose(result);
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>{this.state.title}</Modal.Title>
          </Modal.Header>
          <Modal.Body>
          {this.state.message}
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)}>OK</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  /**
   * javscript core code
   */
  var params = getQueryParams(location.hash);

  var message="Loading data...";
  ReactDOM.render(
    <SpinnerModal show={true} message={message} />,
    document.getElementById('spinner')
  );
  /**
   * Get server parameters
   * And initialize application
   */
  $.ajax({
    method: "GET",
    url: oauth.glewlwyd_server_url + "/config"
  })
  .done(function (result) {
    oauth.admin_scope = result.admin_scope + " " + result.profile_scope;
    oauth.api_prefix = result.api_prefix;
    init();
  })
  .fail(function (error) {
    if (error.status === 401) {
      oauth.access_token = false;
      currentUser.loggedIn = false;
      ReactDOM.render(
        <LoginComponent user={currentUser} />,
        document.getElementById('LoginComponent')
      );
    }
    ReactDOM.render(
      <SpinnerModal show={false} />,
      document.getElementById('spinner')
    );
  });
    
});
