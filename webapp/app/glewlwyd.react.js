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

var Alert = ReactBootstrap.Alert;
var Button = ReactBootstrap.Button;
var Checkbox = ReactBootstrap.Checkbox;
var Modal = ReactBootstrap.Modal;

$(function() {
  // Global lists
  var scopeList = [];
  var resourceList = [];
  var authorizationTypeList = [];
  
  // Config variables
  var access_token = "access_token";
  var access_token_expires = 3600;
  
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
  
  // Get OAuth2 token
  var oauth = {
    access_token: false,
    client_id: "g_admin",
    redirect_uri: "../app/index.html",
    scope: "g_admin"
  }
  
  var currentUser = {loggedIn: false, name: "", email: ""};

  // Function that will be used on every API call
  function APIRequest (method, url, data) {
    return $.ajax({
      method: method,
      url: url,
      data: JSON.stringify(data),
      contentType: data?"application/json; charset=utf-8":null,
      headers: {"Authorization": "Bearer " + oauth.access_token}
    })
    .fail(function (error) {
      if (error.status === 401) {
        oauth.access_token = false;
        currentUser.loggedIn = false;
        ReactDOM.render(
          <LoginComponent user={currentUser} oauth={oauth} />,
          document.getElementById('LoginComponent')
        );
      }
    });
  }

  // Load all lists at startup
  function loadLists () {
    var promises = [
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/")
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
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {
        search: "", 
        offset: 0, 
        limit: 10, 
        users: this.props.users, 
        showModal: false, 
        editUser: { scope: [] }, 
        add: false, 
        userScopeList: [], 
        selectedScope: selectedScope,
        passwordInvalid: false,
        loginInvalid: true,
        showConfirmModal: false,
        messageConfirmModal: "",
        showAlertModal: false,
        messageAlertModal: ""
      };
      
      this.handleSearch = this.handleSearch.bind(this);
      this.handleChangeSearch = this.handleChangeSearch.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      this.userDetails = this.userDetails.bind(this);
      
      // Modal functions
      this.openModalAdd = this.openModalAdd.bind(this);
      this.closeUserModal = this.closeUserModal.bind(this);
      this.saveUserModal = this.saveUserModal.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.handleChangeSource = this.handleChangeSource.bind(this);
      this.handleChangeLogin = this.handleChangeLogin.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeEmail = this.handleChangeEmail.bind(this);
      this.handleChangePassword = this.handleChangePassword.bind(this);
      this.handleChangeConfirmPassword = this.handleChangeConfirmPassword.bind(this);
      this.handleChangeScopeSelected = this.handleChangeScopeSelected.bind(this);
      this.handleChangeEnabled = this.handleChangeEnabled.bind(this);
      this.addScope = this.addScope.bind(this);
      this.removeScope = this.removeScope.bind(this);
      
      this.openModalDelete = this.openModalDelete.bind(this);
      this.okConfirmModal = this.okConfirmModal.bind(this);
      this.cancelConfirmModal = this.cancelConfirmModal.bind(this);
      
      this.openAlertModal = this.openAlertModal.bind(this);
      this.closeAlertModal = this.closeAlertModal.bind(this);
    }
    
    handleChangeSearch (event) {
      this.setState({search: event.target.value});
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      var offset = this.state.offset;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {limit: limit};
      });
    }
    
    handlePreviousPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset-limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleNextPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset+limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleSearch (event) {
      this.runSearch(this.state.search, this.state.offset, this.state.limit);
      event.preventDefault();
    }
    
    userDetails (user) {
      ReactDOM.render(
        <UserDetails user={user} />,
        document.getElementById('userDetails')
      );
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + user.login + "/session/")
      .then(function (result) {
        ReactDOM.render(
          <UserSessionTable sessionList={result} login={user.login}/>,
          document.getElementById('userSessionTable')
        );
      });
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + user.login + "/refresh_token/")
      .then(function (result) {
        ReactDOM.render(
          <UserTokenTable tokenList={result} login={user.login}/>,
          document.getElementById('userTokenTable')
        );
      });
      $('.nav-tabs a[href="#userDetail"]').tab('show');
    }
    
    // Modal functions
    openModalAdd (event) {
      event.preventDefault();
      this.setState({showModal: true, editUser: {enabled: true,  scope: [], source: "database"}, add: true, userScopeList: [], loginInvalid: true});
    }
    
    openModalEdit (user) {
      var cloneUser = $.extend({}, user);
      this.setState({showModal: true, editUser: cloneUser, add: false, loginInvalid: false});
    }
    
    openModalDelete (user) {
      var message = "Are your sure you want to delete user '" + user.login + "'";
      this.setState({showConfirmModal: true, messageConfirmModal: message, editUser: user});
    }
    
    okConfirmModal (event) {
      event.preventDefault();
      var self = this;
      APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.state.editUser.login)
      .then(function (result) {
          var users = self.state.users;
          for (var key in users) {
            if (users[key].login === self.state.editUser.login) {
              users.splice(key, 1);
              break;
            }
          };
          self.setState({users: users});
      })
      .done(function (result) {
        self.setState({showConfirmModal: false});
      });
    }
    
    cancelConfirmModal () {
      this.setState({showConfirmModal: false});
    }
    
    openAlertModal (message) {
      this.setState({showAlertModal: true, messageAlertModal: message});
    }
    
    closeAlertModal () {
      this.setState({showAlertModal: false});
    }
    
    closeUserModal(result, value) {
      this.setState({showModal: false});
    }
    
    saveUserModal (event) {
      event.preventDefault();
      var self = this;
      if (this.state.add) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + self.state.editUser.login)
        .then(function (result) {
          self.openAlertModal("Error, login '" + self.state.editUser.login + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/", self.state.editUser)
          .then(function (result) {
            var users = self.state.users;
            self.state.editUser.password = "";
            self.state.editUser.confirmPassword = "";
            users.push(self.state.editUser);
            self.setState({users: users});
          })
          .fail(function (error) {
            self.openAlertModal("Error adding user");
          })
          .done(function (result) {
            self.setState({showModal: false});
          });
        })
        
      } else {
        APIRequest("PUT", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.state.editUser.login, this.state.editUser)
        .then(function () {
          var users = self.state.users;
          for (var key in users) {
            if (users[key].login === self.state.editUser.login) {
              users[key] = self.state.editUser;
            }
          };
          self.setState({users: users});
        })
        .done(function (result) {
          self.setState({showModal: false});
        });
      }
    }
    
    handleChangeSource (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.source = event.target.value;
      this.setState({editUser: newUser});
    }
    
    handleChangeLogin (event) {
      var isInvalid = !event.target.value;
      var newUser = $.extend({}, this.state.editUser);
      newUser.login = event.target.value || "";
      this.setState({editUser: newUser, loginInvalid: isInvalid});
    }
    
    handleChangeName (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.name = event.target.value || "";
      this.setState({editUser: newUser});
    }
    
    handleChangeEmail (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.email = event.target.value || "";
      this.setState({editUser: newUser});
    }
    
    handleChangePassword (event) {
      var isInvalid = (!!event.target.value || !!this.state.editUser.confirmPassword) && (event.target.value !== this.state.editUser.confirmPassword || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.editUser);
      newUser.password = event.target.value || "";
      this.setState({editUser: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeConfirmPassword (event) {
      var isInvalid = (!!this.state.editUser.password || !!event.target.value) && (this.state.editUser.password !== event.target.value || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.editUser);
      newUser.confirmPassword = event.target.value || "";
      this.setState({editUser: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeScopeSelected (event) {
      this.setState({selectedScope: event.target.value});
    }
    
    removeScope (scope, event) {
      event.preventDefault();
      var newUser = $.extend({}, this.state.editUser);
      newUser.scope.splice(newUser.scope.indexOf(scope), 1);
      this.setState({editUser: newUser});
    }
    
    addScope (event) {
      var newUser = $.extend({}, this.state.editUser);
      if (this.state.editUser.scope.indexOf(this.state.selectedScope) == -1) {
        newUser.scope.push(this.state.selectedScope);
        this.setState({editUser: newUser});
      }
    }
    
    handleChangeEnabled (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.enabled = !newUser.enabled;
      this.setState({editUser: newUser});
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching users");
        });
      } else {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + "?limit=" + limit + "&offset=" + offset)
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

    render() {
      var self = this;
      var allScopeList = [];
      scopeList.forEach(function (scope) {
        allScopeList.push(<option value={scope.name} key={scope.name}>{scope.name}</option>)
      });
      var rows = [];
      this.state.users.forEach(function(user) {
        rows.push(
        <tr key={user.login}>
          <td>{user.source}</td>
          <td>{user.login}</td>
          <td>{user.name}</td>
          <td>{user.email}</td>
          <td>{user.scope.join(", ")}</td>
          <td>{user.enabled?"true":"false"}</td>
          <td>
            <div className="input-group">
              <div className="input-group-btn">
                <Button className="btn btn-default" onClick={() => self.userDetails(user)}>
                  <i className="glyphicon glyphicon-eye-open"></i>
                </Button>
                <Button className="btn btn-default" onClick={() => self.openModalEdit(user)}>
                  <i className="glyphicon glyphicon-pencil"></i>
                </Button>
                <Button className="btn btn-default" onClick={() => self.openModalDelete(user)}>
                  <i className="glyphicon glyphicon-trash"></i>
                </Button>
              </div>
            </div>
          </td>
        </tr>);
      });
      var previousOpts = {};
      if (this.state.offset === 0) {
        previousOpts["disabled"] = "disabled";
      }
      var userScopeList = [];
      this.state.editUser.scope.forEach(function (scope) {
        userScopeList.push(
          <span className="tag label label-info" key={scope}>
            <span>{scope}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeScope(scope, evt)}>
              <i className="remove glyphicon glyphicon-remove-sign glyphicon-white"></i>
            </a>
          </span>
        );
      });
      
      return (
        <div>
          <form onSubmit={this.handleSearch}>
            <div className="input-group row">
              <input type="text" className="form-control" placeholder="Search" value={this.state.search} onChange={this.handleChangeSearch}/>
              <div className="input-group-btn">
                <Button className="btn btn-default" onClick={this.handleSearch}>
                  <i className="glyphicon glyphicon-search"></i>
                </Button>
                <Button className="btn btn-default" onClick={this.openModalAdd}>
                  <i className="glyphicon glyphicon-plus"></i>
                </Button>
              </div>
            </div>
          </form>
          <div className="row">
            <div className="col-md-3">
              <div className="input-group">
                <div className="input-group-btn">
                  <button className="btn btn-default" {...previousOpts} type="button" onClick={this.handlePreviousPage}><i className="icon-resize-small fa fa-chevron-left"></i></button>
                </div>
                <div>
                  <select className="form-control" onChange={this.handleChangeLimit} value={this.state.limit}>
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                  </select>
                </div>
                <div className="input-group-btn">
                  <Button className="btn btn-default" type="button" onClick={this.handleNextPage}><i className="icon-resize-small fa fa-chevron-right"></i></Button>
                </div>
              </div>
            </div>
            <div className="col-md-9 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Source</th>
                <th>Login</th>
                <th>Name</th>
                <th>E-mail</th>
                <th>Scopes</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
          <Modal show={this.state.showModal} onHide={this.closeUserModal}>
            <Modal.Header closeButton>
              <Modal.Title>User</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="userSource">Source</label>
                </div>
                <div className="col-md-6">
                  <select className="form-control" name="userSource" id="userSource" value={this.state.editUser.source} onChange={this.handleChangeSource}>
                    <option value="ldap">LDAP</option>
                    <option value="database">Database</option>
                  </select>
                </div>
              </div>
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="userLogin">Login</label>
                </div>
                <div className={this.state.loginInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="text" name="userLogin" id="userLogin" disabled={!this.state.add?"disabled":""} placeholder="User Login" value={this.state.editUser.login} onChange={this.handleChangeLogin}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userPassword">Password</label>
                </div>
                <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="password" name="userPassword" id="userPassword" placeholder="User password" onChange={this.handleChangePassword} value={this.state.editUser.password}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userPasswordConfirm">Confirm password</label>
                </div>
                <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="password" name="userPasswordConfirm" id="userPasswordConfirm" placeholder="Confirm User password" onChange={this.handleChangeConfirmPassword} value={this.state.editUser.confirmPassword}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userName">Name</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="userName" id="userName" placeholder="Fullname" value={this.state.editUser.name} onChange={this.handleChangeName}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userEmail">Email</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="userEmail" id="userEmail" placeholder="User e-mail" value={this.state.editUser.email} onChange={this.handleChangeEmail}></input>
                </div>
              </div>
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
                      <button type="button" name="addScope" id="addScope" className="btn btn-default" onClick={this.addScope}>
                        <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                </div>
                <div className="col-md-6" id="userScopeValue">
                {userScopeList}
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label>Enabled</label>
                </div>
                <div className="col-md-6">
                  <Checkbox validationState="success" checked={this.state.editUser.enabled?true:false} onChange={this.handleChangeEnabled}></Checkbox>
                </div>
              </div>
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.saveUserModal} disabled={this.state.passwordInvalid||this.state.loginInvalid?true:false}>Save</Button>
              <Button onClick={this.closeUserModal}>Cancel</Button>
            </Modal.Footer>
          </Modal>
          <Modal show={this.state.showConfirmModal} onHide={this.cancelConfirmModal}>
            <Modal.Header closeButton>
              <Modal.Title>Delete user</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageConfirmModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.okConfirmModal}>OK</Button>
              <Button onClick={this.cancelConfirmModal}>Cancel</Button>
            </Modal.Footer>
          </Modal>
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
        </div>
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
        search: "", 
        offset: 0, 
        limit: 10, 
        clients: this.props.clients, 
        showModal: false, 
        editClient: { scope: [], redirect_uri: [] }, 
        add: false, 
        redirectUri: "",
        redirectUriName: "",
        selectedScope: selectedScope,
        passwordInvalid: false,
        clientIdInvalid: true,
        redirectUriNameInvalid: false,
        redirectUriInvalid: false,
        showConfirmModal: false,
        messageConfirmModal: "",
        showAlertModal: false,
        messageAlertModal: ""
      };
      
      this.handleSearch = this.handleSearch.bind(this);
      this.handleChangeSearch = this.handleChangeSearch.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      
      // Modal functions
      this.openModalAdd = this.openModalAdd.bind(this);
      this.closeClientModal = this.closeClientModal.bind(this);
      this.saveClientModal = this.saveClientModal.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.handleChangeSource = this.handleChangeSource.bind(this);
      this.handleChangeClientId = this.handleChangeClientId.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeDescription = this.handleChangeDescription.bind(this);
      this.handleChangeConfidential = this.handleChangeConfidential.bind(this);
      this.handleChangePassword = this.handleChangePassword.bind(this);
      this.handleChangeConfirmPassword = this.handleChangeConfirmPassword.bind(this);
      this.handleChangeScopeSelected = this.handleChangeScopeSelected.bind(this);
      this.handleChangeRedirectUriName = this.handleChangeRedirectUriName.bind(this);
      this.handleChangeRedirectUri = this.handleChangeRedirectUri.bind(this);
      this.addRedirectUri = this.addRedirectUri.bind(this);
      this.handleChangeEnabled = this.handleChangeEnabled.bind(this);
      this.addScope = this.addScope.bind(this);
      this.removeScope = this.removeScope.bind(this);
      
      this.openModalDelete = this.openModalDelete.bind(this);
      this.deleteClient = this.deleteClient.bind(this);
      
      this.openAlertModal = this.openAlertModal.bind(this);
    }
    
    handleChangeSearch (event) {
      this.setState({search: event.target.value});
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      var offset = this.state.offset;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {limit: limit};
      });
    }
    
    handlePreviousPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset-limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleNextPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset+limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleSearch (event) {
      this.runSearch(this.state.search, this.state.offset, this.state.limit);
      event.preventDefault();
    }
    
    // Modal functions
    openModalAdd (event) {
      event.preventDefault();
      this.setState({
        showModal: true, 
        editClient: {
          enabled: true,
          scope: [], 
          redirect_uri: [], 
          source: "database", 
          confidential: false, 
          password: "", 
          confirmPassword: ""
        }, 
        add: true, 
        clientScopeList: [], 
        clientIdInvalid: true,
        redirectUriNameInvalid: true,
        redirectUriInvalid: true
      });
    }
    
    openModalEdit (client) {
      var cloneClient = $.extend({}, client);
      this.setState({showModal: true, editClient: cloneClient, add: false, clientIdInvalid: false});
    }
    
    openModalDelete (client) {
      var message = "Are your sure you want to delete client '" + client.client_id + "'";
      ReactDOM.render(
        <ConfirmModal show={true} title={"Client"} message={message} onClose={this.deleteClient} />,
        document.getElementById('modal')
      );
      this.setState({editClient: client});
    }
    
    deleteClient (result) {
      var self = this;
      result && APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/" + this.state.editClient.client_id)
      .then(function (result) {
          var clients = self.state.clients;
          for (var key in clients) {
            if (clients[key].client_id === self.state.editClient.client_id) {
              clients.splice(key, 1);
              break;
            }
          };
          self.setState({clients: clients});
      })
      .done(function (result) {
        self.setState({showConfirmModal: false});
      });
    }
    
    openAlertModal (message) {
      ReactDOM.render(
        <MessageModal show={true} title={"Client"} message={message} />,
        document.getElementById('modal')
      );
    }
    
    closeClientModal(result, value) {
      this.setState({showModal: false});
    }
    
    saveClientModal (event) {
      event.preventDefault();
      var self = this;
      if (this.state.add) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/" + self.state.editClient.client_id)
        .then(function (result) {
          self.openAlertModal("Error, client_id '" + self.state.editClient.client_id + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/", self.state.editClient)
          .then(function (result) {
            var clients = self.state.clients;
            self.state.editClient.password = "";
            self.state.editClient.confirmPassword = "";
            clients.push(self.state.editClient);
            self.setState({clients: clients});
          })
          .fail(function (error) {
            self.openAlertModal("Error adding client");
          })
          .done(function (result) {
            self.setState({showModal: false});
          });
        });
        
      } else {
        APIRequest("PUT", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/" + this.state.editClient.client_id, this.state.editClient)
        .then(function () {
          var clients = self.state.clients;
          for (var key in clients) {
            if (clients[key].client_id === self.state.editClient.client_id) {
              clients[key] = self.state.editClient;
            }
          };
          self.setState({clients: clients});
        })
        .done(function (result) {
          self.setState({showModal: false});
        });
      }
    }
    
    handleChangeSource (event) {
      var newClient = $.extend({}, this.state.editClient);
      newClient.source = event.target.value;
      this.setState({editClient: newClient});
    }
    
    handleChangeClientId (event) {
      var isInvalid = !event.target.value;
      var newClient = $.extend({}, this.state.editClient);
      newClient.client_id = event.target.value || "";
      this.setState({editClient: newClient, clientIdInvalid: isInvalid});
    }
    
    handleChangeName (event) {
      var newClient = $.extend({}, this.state.editClient);
      newClient.name = event.target.value || "";
      this.setState({editClient: newClient});
    }
    
    handleChangeDescription (event) {
      var newClient = $.extend({}, this.state.editClient);
      newClient.description = event.target.value || "";
      this.setState({editClient: newClient});
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
        var newClient = $.extend({}, this.state.editClient);
        newClient.redirect_uri.push({name: this.state.redirectUriName, uri: this.state.redirectUri});
        this.setState({editClient: newClient});
      }
    }
    
    handleChangeConfidential (event) {
      var newClient = $.extend({}, this.state.editClient);
      newClient.confidential = !newClient.confidential;
      var isInvalid = newClient.confidential && (this.state.editClient.password !== this.state.editClient.confirmPassword || !this.state.editClient.password || this.state.editClient.password.length < 8);
      this.setState({editClient: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangePassword (event) {
      var isInvalid = this.state.editClient.confidential && (event.target.value !== this.state.editClient.confirmPassword || event.target.value.length < 8);
      var newClient = $.extend({}, this.state.editClient);
      newClient.password = event.target.value || "";
      this.setState({editClient: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangeConfirmPassword (event) {
      var isInvalid = this.state.editClient.confidential && (event.target.value !== this.state.editClient.password || !this.state.editClient.password || this.state.editClient.password.length < 8);
      var newClient = $.extend({}, this.state.editClient);
      newClient.confirmPassword = event.target.value || "";
      this.setState({editClient: newClient, passwordInvalid: isInvalid});
    }
    
    handleChangeScopeSelected (event) {
      this.setState({selectedScope: event.target.value});
    }
    
    removeScope (scope, event) {
      event.preventDefault();
      var newClient = $.extend({}, this.state.editClient);
      newClient.scope.splice(newClient.scope.indexOf(scope), 1);
      this.setState({editClient: newClient});
    }
    
    addScope (event) {
      var newClient = $.extend({}, this.state.editClient);
      if (this.state.editClient.scope.indexOf(this.state.selectedScope) == -1) {
        newClient.scope.push(this.state.selectedScope);
        this.setState({editClient: newClient});
      }
    }
    
    handleChangeEnabled (event) {
      var newClient = $.extend({}, this.state.editClient);
      newClient.enabled = !newClient.enabled;
      this.setState({editClient: newClient});
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            clients: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching clients");
        });
      } else {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/" + "?limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            clients: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching clients");
        });
      }
    }

    render() {
      var self = this;
      var allScopeList = [];
      scopeList.forEach(function (scope) {
        allScopeList.push(<option value={scope.name} key={scope.name}>{scope.name}</option>)
      });
      var rows = [];
      this.state.clients.forEach(function(client) {
        rows.push(
          <ClientRow client={client} openModalEdit={this.openModalEdit} openModalDelete={this.openModalDelete} />
        );
      });
      var previousOpts = {};
      if (this.state.offset === 0) {
        previousOpts["disabled"] = "disabled";
      }
      var clientScopeList = [];
      this.state.editClient.scope.forEach(function (scope) {
        clientScopeList.push(
          <span className="tag label label-info" key={scope}>
            <span>{scope}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeScope(scope, evt)}>
              <i className="remove glyphicon glyphicon-remove-sign glyphicon-white"></i>
            </a>
          </span>
        );
      });
      var clientRedirectUriList = [];
      this.state.editClient.redirect_uri.forEach(function (redirect_uri, index) {
        clientRedirectUriList.push(
          <span className="tag label label-info hide-overflow" key={index} data-toggle="tooltip" title={redirect_uri.uri}>
            <a href="" onClick={(evt) => self.removeRedirectUri(redirect_uri.name, evt)}>
              <i className="remove glyphicon glyphicon-remove-sign glyphicon-white"></i>
            </a>
            <span>&nbsp;{redirect_uri.name + " (" + redirect_uri.uri + ")"}</span>
          </span>
        );
      });
      
      return (
        <div>
          <form onSubmit={this.handleSearch}>
            <div className="input-group row">
              <input type="text" className="form-control" placeholder="Search" value={this.state.search} onChange={this.handleChangeSearch}/>
              <div className="input-group-btn">
                <Button className="btn btn-default" onClick={this.handleSearch}>
                  <i className="glyphicon glyphicon-search"></i>
                </Button>
                <Button className="btn btn-default" onClick={this.openModalAdd}>
                  <i className="glyphicon glyphicon-plus"></i>
                </Button>
              </div>
            </div>
          </form>
          <div className="row">
            <div className="col-md-3">
              <div className="input-group">
                <div className="input-group-btn">
                  <button className="btn btn-default" {...previousOpts} type="button" onClick={this.handlePreviousPage}><i className="icon-resize-small fa fa-chevron-left"></i></button>
                </div>
                <div>
                  <select className="form-control" onChange={this.handleChangeLimit} value={this.state.limit}>
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                  </select>
                </div>
                <div className="input-group-btn">
                  <Button className="btn btn-default" type="button" onClick={this.handleNextPage}><i className="icon-resize-small fa fa-chevron-right"></i></Button>
                </div>
              </div>
            </div>
            <div className="col-md-9 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Source</th>
                <th>Client Id</th>
                <th>Name</th>
                <th>Description</th>
                <th>Confidential</th>
                <th>Enabled</th>
                <th>Scopes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
          <Modal show={this.state.showModal} onHide={this.closeClientModal}>
            <Modal.Header closeButton>
              <Modal.Title>Client</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="clientSource">Source</label>
                </div>
                <div className="col-md-6">
                  <select className="form-control" name="clientSource" id="clientSource" value={this.state.editClient.source} onChange={this.handleChangeSource}>
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
                  <input className="form-control" type="text" name="clientId" id="clientId" disabled={!this.state.add?"disabled":""} placeholder="Client Id" value={this.state.editClient.client_id} onChange={this.handleChangeClientId}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="clientName">Name</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="clientName" id="clientName" placeholder="Fullname" value={this.state.editClient.name} onChange={this.handleChangeName}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="clientDescription">Description</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="clientDescription" id="clientDescription" placeholder="Client description" value={this.state.editClient.description} onChange={this.handleChangeDescription}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label>Confidential</label>
                </div>
                <div className="col-md-6">
                  <Checkbox validationState="success" checked={this.state.editClient.confidential?true:false} onChange={this.handleChangeConfidential}></Checkbox>
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
                         disabled={this.state.editClient.confidential?false:true}
                         onChange={this.handleChangePassword} 
                         value={this.state.editClient.password}></input>
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
                         disabled={this.state.editClient.confidential?false:true}
                         onChange={this.handleChangeConfirmPassword} 
                         value={this.state.editClient.confirmPassword}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="clientScope">Scopes</label>
                </div>
                <div className="col-md-6">
                  <div className="input-group">
                    <select id="clientScope" name="clientScope" className="form-control" value={this.state.scopeSelected} onChange={this.handleChangeScopeSelected}>
                      {allScopeList}
                    </select>
                    <div className="input-group-btn ">
                      <button type="button" name="addScope" id="addScope" className="btn btn-default" onClick={this.addScope}>
                        <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                </div>
                <div className="col-md-6" id="clientScopeValue">
                {clientScopeList}
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="clientScope">Redirect URIs</label>
                </div>
                <div className="col-md-6">
                  <div className={this.state.redirectUriInvalid?"has-error":""}>
                    <input className="form-control" type="text" placeholder="URI" data-toggle="tooltip" title="Redirect uri must start with http:// or https://" value={this.state.redirectUri} onChange={this.handleChangeRedirectUri}></input>
                  </div>
                  <div>
                    <div className={this.state.redirectUriNameInvalid?"input-group has-error":"input-group"}>
                      <input className="form-control" type="text" placeholder="Name" value={this.state.redirectUriName} onChange={this.handleChangeRedirectUriName}></input>
                      <div className="input-group-btn ">
                        <button type="button" 
                                name="addScope" 
                                id="addScope" 
                                className="btn btn-default" 
                                disabled={this.state.redirectUriNameInvalid||this.state.redirectUriInvalid?true:false}
                                onClick={this.addRedirectUri}>
                          <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                </div>
                <div className="col-md-6" id="clientScopeValue">
                {clientRedirectUriList}
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label>Enabled</label>
                </div>
                <div className="col-md-6">
                  <Checkbox validationState="success" checked={this.state.editClient.enabled?true:false} onChange={this.handleChangeEnabled}></Checkbox>
                </div>
              </div>
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.saveClientModal} disabled={this.state.passwordInvalid||this.state.clientIdInvalid||this.state.editClient.redirect_uri.length===0?true:false}>Save</Button>
              <Button onClick={this.closeClientModal}>Cancel</Button>
            </Modal.Footer>
          </Modal>
        </div>
      );
    }
  }
  
  function ClientRow (props) {
    return (
      <tr>
        <td>{props.client.source}</td>
        <td>{props.client.name}</td>
        <td>{props.client.client_id}</td>
        <td>{props.client.description}</td>
        <td>{String(props.client.confidential)}</td>
        <td>{String(props.client.enabled)}</td>
        <td>{props.client.scope.join(", ")}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.client)}>
                <i className="glyphicon glyphicon-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.client)}>
                <i className="glyphicon glyphicon-trash"></i>
              </Button>
            </div>
          </div>
        </td>
      </tr>
    );
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
        APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/" + this.state.editScope.name)
        .then(function (result) {
            var scopes = self.state.scopes;
            for (var key in scopes) {
              if (scopes[key].name === self.state.editScope.name) {
                scopes.splice(key, 1);
                break;
              }
            };
            self.setState({scopes: scopes});
        })
        .done(function (result) {
          self.setState({showConfirmModal: false});
        });
      }
    }
    
    closeScopeModal(result, value) {
      this.setState({showModal: false});
    }
    
    saveScope (add, scope) {
      var self = this;
      if (add) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/" + scope.name)
        .then(function (result) {
          self.openAlertModal("Error, scope '" + scope.name + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/", scope)
          .then(function (result) {
            var scopes = self.state.scopes;
            scopes.push(scope);
            self.setState({scopes: scopes});
          })
          .fail(function (error) {
            self.openAlertModal("Error adding scope");
          })
          .done(function (result) {
            self.setState({showModal: false});
          });
        })
        
      } else {
        APIRequest("PUT", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/" + scope.name, scope)
        .then(function () {
          var scopes = self.state.scopes;
          for (var key in scopes) {
            if (scopes[key].name === scope.name) {
              scopes[key] = scope;
            }
          };
          self.setState({scopes: scopes});
        })
        .done(function (result) {
          self.setState({showModal: false});
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
          <Button className="btn btn-default" onClick={this.openModalAdd}>
            <i className="glyphicon glyphicon-plus"></i>
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
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.scope)}>
                <i className="glyphicon glyphicon-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.scope)}>
                <i className="glyphicon glyphicon-trash"></i>
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
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
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
                       onChange={this.handleChangeName}></input>
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
                       onChange={this.handleChangeDescription}></input>
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
        APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/" + this.state.editResource.name)
        .then(function (result) {
            var resources = self.state.resources;
            for (var key in resources) {
              if (resources[key].name === self.state.editResource.name) {
                resources.splice(key, 1);
                break;
              }
            };
            self.setState({resources: resources});
        })
        .done(function (result) {
          self.setState({showConfirmModal: false});
        });
      }
    }
    
    saveResource (add, resource) {
      var self = this;
      if (add) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/" + resource.name)
        .then(function (result) {
          self.openAlertModal("Error, resource '" + resource.name + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/", resource)
          .then(function (result) {
            var resources = self.state.resources;
            resources.push(resource);
            self.setState({resources: resources});
          })
          .fail(function (error) {
            self.openAlertModal("Error adding resource");
          })
          .done(function (result) {
            self.setState({showModal: false});
          });
        })
        
      } else {
        APIRequest("PUT", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/" + resource.name, resource)
        .then(function () {
          var resources = self.state.resources;
          for (var key in resources) {
            if (resources[key].name === resource.name) {
              resources[key] = resource;
            }
          };
          self.setState({resources: resources});
        })
        .done(function (result) {
          self.setState({showModal: false});
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
          <Button className="btn btn-default" onClick={this.openModalAdd}>
            <i className="glyphicon glyphicon-plus"></i>
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
        <td>{props.resource.uri}</td>
        <td>{props.resource.scope.join(", ")}</td>
        <td>
          <div className="input-group">
            <div className="input-group-btn">
              <Button className="btn btn-default" onClick={() => props.openModalEdit(props.resource)}>
                <i className="glyphicon glyphicon-pencil"></i>
              </Button>
              <Button className="btn btn-default" onClick={() => props.openModalDelete(props.resource)}>
                <i className="glyphicon glyphicon-trash"></i>
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
            <Modal.Title>Scope</Modal.Title>
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
                       onChange={this.handleChangeName}></input>
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
                       onChange={this.handleChangeDescription}></input>
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
                       onChange={this.handleChangeUri}></input>
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
        {props.session.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.session, event)}>
            <i className="glyphicon glyphicon-trash"></i>
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
    
    refreshSessionList (event) {
      event.preventDefault();
      var self = this;
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.props.login + "/session/")
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
        APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.props.login + "/session/", {session_hash: this.state.currentSession.session_hash})
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
          <h3>Sessions&nbsp;
            <small>
              <Button className="btn" onClick={(event) => this.refreshSessionList(event)}>
                <i className="fa fa-refresh" aria-hidden="true"></i>
              </Button>
            </small>
          </h3>
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
        {props.token.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.token, event)}>
            <i className="glyphicon glyphicon-trash"></i>
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
    
    refreshTokenList (event) {
      event.preventDefault();
      var self = this;
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.props.login + "/refresh_token/")
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
        APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.props.login + "/refresh_token/", {token_hash: this.state.currentToken.token_hash})
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
          <h3>Refresh tokens&nbsp;
            <small>
              <Button className="btn" onClick={(event) => this.refreshTokenList(event)}>
                <i className="fa fa-refresh" aria-hidden="true"></i>
              </Button>
            </small>
          </h3>
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
      <span>Hello {props.user.name}&nbsp;</span>
    );
  }

  function ConnectMessage (props) {
    return (
      <span>Please log in to the application&nbsp;</span>
    );
  }

  class LogoutButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogout = this.handleLogout.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogout}>
        <i className="fa fa-sign-out" aria-hidden="true"></i>
        &nbsp;Log out
      </button>);
    }
    
    handleLogout() {
      this.props.oauth.access_token = false;
      $.removeCookie(access_token);
      this.props.user.loggedIn = false;
      ReactDOM.render(
        <LoginComponent user={this.props.user} oauth={this.props.oauth} />,
        document.getElementById('LoginComponent')
      );
    }
  }

  class LoginButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogin = this.handleLogin.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogin}>
        <i className="fa fa-sign-in" aria-hidden="true"></i>
        &nbsp;Log in
      </button>);
    }
    
    handleLogin() {
      document.location = "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth?response_type=token&client_id="+this.props.oauth.client_id+"&redirect_uri="+this.props.oauth.redirect_uri+"&scope="+this.props.oauth.scope;
    }
  }

  function LoginComponent (props) {
    if (props.user.loggedIn) {
      return (
        <div>
          <LoginInformation user={props.user} oauth={props.oauth} />
          <LogoutButton user={props.user} oauth={props.oauth} />
        </div>
      );
    } else {
      return (
        <div>
          <ConnectMessage />
          <LoginButton oauth={props.oauth} />
        </div>
      );
    }
  }

  /**
   * Scope management
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
          <span className="tag label label-info" key={index}>
            <span>{scope}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeScope(scope, evt)}>
              <i className="remove glyphicon glyphicon-remove-sign glyphicon-white"></i>
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
                  <button type="button" name="addScope" id="addScope" className="btn btn-default" onClick={this.addScope}>
                    <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                  </button>
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
          <button type="button" className="btn btn-danger" onClick={this.handleToggleAuthType} >Disable</button>
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
          <button type="button" className="btn btn-success" onClick={this.handleToggleAuthType} >Enable</button>
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
      APIRequest("PUT","https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/" + this.props.authType.name, {description: this.props.authType.description, enabled: !this.state.enabled})
      .done(function (result) {
        self.setState(prevState => ({
          enabled: !prevState.enabled
        }));
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
            <AuthTypeEnableButton authType={this.props.authType} oauth={this.props.oauth} />
          </td>
        </tr>
      );
    }
  }

  function AuthorizationTypeList (props) {
    var rows = [];
    props.authTypeList.forEach(function(authType) {
      rows.push(<AuthorizationType authType={authType} key={authType.name} oauth={props.oauth} />);
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
   * javscript core code
   */
  var params = getQueryParams(location.hash);

  /**
   * get access_token from url, or from cookie
   */
  if (params.access_token) {
    oauth.access_token = params.access_token;
    var expires = new Date();
    expires.setSeconds(expires.getSeconds() + access_token_expires);
    $.cookie(access_token, params.access_token, {expires: expires});
    document.location = "#";
  } else if (params.error) {
    ReactDOM.render(
      <MessageModal show={true} title={"Error"} message={"You are not authorized to connect to this application"} />,
      document.getElementById('modal')
    );
  } else if ($.cookie(access_token)) {
    oauth.access_token = $.cookie(access_token);
  }

  /**
   * If an acces_token is present, use it to get all lists
   * if no access_token, display the login button
   */
  if (oauth.access_token) {
    APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth/user/")
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
        <LoginComponent user={currentUser} oauth={oauth} />,
        document.getElementById('LoginComponent')
      );
    });
  } else {
    ReactDOM.render(
      <LoginComponent user={currentUser} oauth={oauth} />,
      document.getElementById('LoginComponent')
    );
  }
  
});
