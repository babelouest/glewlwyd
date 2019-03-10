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
      canContinue: !props.scheme
    };
    
    this.parseSchemes = this.parseSchemes.bind(this);
    
    this.parseSchemes();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      client: nextProps.client,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      canContinue: !nextProps.scheme
    }, () => {
      this.parseSchemes();
    });
  }
  
  parseSchemes() {
    var canContinue = !this.state.scheme;
    var schemeForm = false;
    var newScheme = this.state.scheme;
    for (var scope in newScheme) {
      if (newScheme[scope].password_required && !newScheme[scope].password_authenticated) {
        scope.isAuth = false;
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
    if (canContinue) {
      messageDispatcher.sendMessage('Buttons', 'enableContinue');
    }
    console.log("plop", {scheme: newScheme, canContinue: canContinue, curSchemeForm: schemeForm});
    this.setState({scheme: newScheme, canContinue: canContinue, curSchemeForm: schemeForm}, () => {
      console.log("scheme");
    });
  }

  render() {
    var scopeList = [];
    var iScope = 0;
    if (!this.state.canContinue) {
      for (var scope in this.state.scheme) {
        var curScope = this.state.scheme[scope];
        if (curScope.isAuth) {
          scopeList.push(
          <li className="list-group-item" key={"scope-"+iScope}>
            <h3><span className="badge badge-success">{curScope.details.display_name}</span></h3>
          </li>
          );
        } else {
          var groupList = [];
          var iGroup = 0;
          for (var group in curScope.schemes) {
            var schemeList = [];
            curScope.schemes[group].forEach((scheme, index) => {
              if (scheme.scheme_authenticated) {
                schemeList.push(<li className="list-group-item" key={"scheme-"+index}><span className="badge badge-success">{scheme.scheme_display_name}</span></li>);
              } else {
                schemeList.push(<li className="list-group-item" key={"scheme-"+index}><span className="badge badge-secondary">{scheme.scheme_display_name}</span></li>);
              }
            });
            groupList.push(<li className="list-inline-item" key={"group-"+iGroup}>
              <ul className="list-group">
                <li className="list-group-item"><span className="badge badge-primary">{group}</span></li>
                {schemeList}
              </ul>
            </li>);
            iGroup++;
          }
          scopeList.push(
            <li className="list-group-item" key={"scope-"+iScope}>
              <h3><span className="badge badge-secondary">{curScope.details.display_name}</span></h3>
              <ul className="list-inline">
                {groupList}
              </ul>
            </li>
          );
        }
        iScope++;
      }
      var schemeForm = "";
      var separator = "";
      console.log(this.state.curSchemeForm);
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
