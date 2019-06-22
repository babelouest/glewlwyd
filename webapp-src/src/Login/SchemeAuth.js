import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import SchemeAuthForm from './SchemeAuthForm';

class SchemeAuth extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      client: props.client,
      scheme: props.scheme,
      currentUser: props.currentUser,
      curSchemeForm: false,
      canContinue: !props.scheme,
      show: props.show
    };
    
    this.parseSchemes = this.parseSchemes.bind(this);
    this.handleSelectScheme = this.handleSelectScheme.bind(this);
    
    this.parseSchemes();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      client: nextProps.client,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      canContinue: !nextProps.scheme,
      show: nextProps.show
    }, () => {
      this.parseSchemes();
    });
  }
  
  parseSchemes() {
    var canContinue = true;
    var schemeForm = false;
    var newScheme = this.state.scheme;
    for (var scope in newScheme) {
      if (newScheme[scope].password_required && !newScheme[scope].password_authenticated) {
        newScheme[scope].isAuth = false;
      } else {
        newScheme[scope].isAuth = true;
        for (var group in newScheme[scope].schemes) {
          var curGroup = newScheme[scope].schemes[group];
          var grpIsAuth = false;
          curGroup.forEach((scheme) => {
            if (scheme.scheme_authenticated) {
              grpIsAuth = true;
            } else if (!grpIsAuth && !schemeForm) {
              schemeForm = scheme;
            }
            if (grpIsAuth && !!schemeForm) {
              schemeForm = false;
            }
          });
          curGroup.isAuth = grpIsAuth;
          if (!grpIsAuth) {
            newScheme[scope].isAuth = false;
          }
        }
      }
      if (!newScheme[scope].isAuth) {
        canContinue = false;
      }
    }
    messageDispatcher.sendMessage('Buttons', {value: "enableContinue", canContinue: canContinue});
    this.setState({scheme: newScheme, canContinue: canContinue, curSchemeForm: schemeForm});
  }
  
  handleSelectScheme(e, scheme) {
    e.preventDefault();
    this.setState({curSchemeForm: scheme});
  }

  render() {
    var scopeList = [];
    var iScope = 0;
    if (!this.state.canContinue) {
      var schemeForm = "";
      var separator = "";
      if (this.state.curSchemeForm) {
        schemeForm = <SchemeAuthForm config={this.state.config} scheme={this.state.curSchemeForm} currentUser={this.state.currentUser}/>;
        separator = <div className="row">
            <div className="col-md-12">
              <hr/>
            </div>
          </div>;
      }
      return (
        <div>
          {schemeForm}
          {separator}
          <div id="accordionScheme">
            <div className="card">
              <div className="card-header" id="headingOne">
                <h5 className="mb-0">
                  <button className="btn btn-link" data-toggle="collapse" data-target="#collapseScheme" aria-expanded="true" aria-controls="collapseScheme">
                    {i18next.t("login.scheme-list-show")}
                  </button>
                </h5>
              </div>
              <div id="collapseScheme" className="collapse" aria-labelledby="headingOne" data-parent="#accordionScheme">
                <div className="card-body">
                  <ul className="list-group">
                    {scopeList}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    } else {
      return (
        <div className="row">
          <div className="col-md-12">
            <h3>{i18next.t("login.wish-message")}</h3>
          </div>
        </div>
      );
    }
  }
}

export default SchemeAuth;
